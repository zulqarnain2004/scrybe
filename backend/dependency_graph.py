"""
dependency_graph.py — EXTRA FEATURE beyond the original CodeSage post.

Builds a module-level import dependency graph (Python: ast-based; JS/TS:
regex-based import extraction) and renders it as a PNG for the PDF report
and Streamlit UI. Also flags circular import chains, which are a common
maintainability smell that static complexity metrics miss entirely.
"""

import ast
import re
import os
import io
from dataclasses import dataclass, field

import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from .ingestion import ProjectMap


@dataclass
class DependencyGraphResult:
    graph: object = None  # networkx.DiGraph
    cycles: list = field(default_factory=list)
    most_depended_on: list = field(default_factory=list)  # [(module, in_degree)]
    image_bytes: bytes | None = None


JS_IMPORT_RE = re.compile(r"""(?:import\s+.*?from\s+['"](\.[^'"]+)['"]|require\(\s*['"](\.[^'"]+)['"]\s*\))""")


def _module_name_for(path: str, root: str) -> str:
    rel = os.path.relpath(path, root)
    rel = re.sub(r"\.(py|js|jsx|ts|tsx)$", "", rel)
    return rel.replace(os.sep, ".")


def _resolve_relative_js(current_file: str, rel_import: str, root: str) -> str | None:
    base_dir = os.path.dirname(current_file)
    candidate = os.path.normpath(os.path.join(base_dir, rel_import))
    for ext in ("", ".js", ".jsx", ".ts", ".tsx", "/index.js", "/index.ts"):
        if os.path.isfile(candidate + ext):
            return _module_name_for(candidate + ext, root)
    return None


def build_dependency_graph(pm: ProjectMap) -> DependencyGraphResult:
    g = nx.DiGraph()
    python_files = {pf.abs_path for pf in pm.files if pf.language == "Python"}
    js_files = {pf.abs_path for pf in pm.files if pf.language in ("JavaScript", "TypeScript")}

    module_names = {p: _module_name_for(p, pm.root_dir) for p in python_files | js_files}
    for name in module_names.values():
        g.add_node(name)

    # Python: AST-based import resolution (accurate)
    py_module_lookup = {name: path for path, name in module_names.items() if path in python_files}
    for path in python_files:
        src_module = module_names[path]
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                tree = ast.parse(f.read(), filename=path)
        except (SyntaxError, OSError):
            continue
        for node in ast.walk(tree):
            imported = None
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported = alias.name  # keep dotted form, e.g. "pkg.b"
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported = node.module  # keep dotted form

            if imported:
                # match against known local modules: exact dotted match, or
                # candidate's dotted path ending with the imported dotted path
                for candidate_name in py_module_lookup:
                    if candidate_name == imported or candidate_name.endswith("." + imported) or imported.endswith("." + candidate_name):
                        if candidate_name != src_module:
                            g.add_edge(src_module, candidate_name)
                        break

    # JS/TS: regex-based relative import resolution
    for path in js_files:
        src_module = module_names[path]
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            continue
        for m in JS_IMPORT_RE.finditer(content):
            rel_import = m.group(1) or m.group(2)
            resolved = _resolve_relative_js(path, rel_import, pm.root_dir)
            if resolved and resolved != src_module:
                g.add_edge(src_module, resolved)

    result = DependencyGraphResult(graph=g)
    try:
        result.cycles = [cycle for cycle in nx.simple_cycles(g) if len(cycle) > 1][:10]
    except Exception:
        result.cycles = []

    in_degrees = sorted(g.in_degree(), key=lambda kv: -kv[1])
    result.most_depended_on = [(n, d) for n, d in in_degrees if d > 0][:10]

    if g.number_of_nodes() > 0 and g.number_of_edges() > 0:
        try:
            result.image_bytes = _render_graph_png(g, result.cycles)
        except Exception:
            result.image_bytes = None

    return result


def _render_graph_png(g: nx.DiGraph, cycles: list) -> bytes:
    cycle_nodes = {n for cyc in cycles for n in cyc}
    plt.figure(figsize=(10, 7))
    try:
        pos = nx.spring_layout(g, k=0.6, seed=42)
        node_colors = ["#e74c3c" if n in cycle_nodes else "#3498db" for n in g.nodes()]
        nx.draw_networkx_nodes(g, pos, node_size=500, node_color=node_colors, alpha=0.9)
        nx.draw_networkx_edges(g, pos, arrows=True, alpha=0.4, arrowsize=12)
        labels = {n: n.split(os.sep)[-1].split(".")[-1] for n in g.nodes()}
        nx.draw_networkx_labels(g, pos, labels=labels, font_size=7)
        plt.axis("off")
        plt.tight_layout()
        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=140)
        buf.seek(0)
        return buf.read()
    finally:
        plt.close()
