"""
doc_generator.py — Generates a project README and per-function documentation
using the actual project structure, language breakdown, and code chunks
(not a generic template). Docstrings are generated per-function from the
same AST chunks used for embeddings, so they're grounded in real code.
"""

import textwrap
from .llm_client import complete
from .embeddings import chunk_project

README_SYSTEM_PROMPT = """You are a senior engineer writing a README for a real project. \
Base every claim strictly on the provided project structure and code excerpts. Do not \
invent features, setup steps, or license information that isn't evidenced by the input. \
If something is unclear (e.g. how to run it), say so rather than guessing confidently."""

DOCSTRING_SYSTEM_PROMPT = """You write concise, accurate docstrings for existing functions. \
Describe only what the code actually does — its parameters, return value, and side effects. \
Do not add commentary about code quality. Output ONLY the docstring text (no code fences, \
no function signature), ready to paste inside the function."""


def generate_readme(pm, analysis, api_key: str | None = None) -> str:
    sample_chunks = chunk_project(pm)[:25]
    excerpt_blob = "\n\n".join(
        f"### {c.file_path} ({c.symbol_name or 'block'}, lines {c.start_line}-{c.end_line})\n"
        f"```\n{c.text[:600]}\n```"
        for c in sample_chunks
    )
    file_tree = "\n".join(sorted(pf.path for pf in pm.files)[:80])

    prompt = textwrap.dedent(f"""
        Project name: {pm.project_name}
        Language breakdown (lines of code): {analysis and pm.language_breakdown}
        Total files: {len(pm.files)}, total LOC: {pm.total_loc}

        File tree (partial):
        {file_tree}

        Representative code excerpts:
        {excerpt_blob[:8000]}

        Write a professional README.md for this project with sections: Overview,
        Features (inferred from the code, not invented), Project Structure, Setup/Installation
        (infer from dependency files if visible, otherwise write "see requirements.txt" style
        guidance generically), and Usage. Keep it grounded in what's actually in the code excerpts.
    """).strip()

    return complete(prompt, api_key=api_key, system=README_SYSTEM_PROMPT, max_tokens=2000)


def generate_function_docstring(chunk, api_key: str | None = None) -> str:
    prompt = textwrap.dedent(f"""
        File: {chunk.file_path}
        Function/class: {chunk.symbol_name}

        Code:
        ```
        {chunk.text[:1500]}
        ```

        Write a docstring for this function/class.
    """).strip()
    return complete(prompt, api_key=api_key, system=DOCSTRING_SYSTEM_PROMPT, max_tokens=300)


def generate_missing_docstrings(pm, max_functions: int = 20, api_key: str | None = None) -> list[dict]:
    """Finds Python functions/classes with no docstring and generates one for each.
    Capped at max_functions to keep API usage predictable on large repos."""
    import ast

    results = []
    count = 0
    for pf in pm.files:
        if pf.language != "Python" or count >= max_functions:
            continue
        try:
            with open(pf.abs_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
            tree = ast.parse(source)
        except (SyntaxError, OSError):
            continue

        lines = source.splitlines()
        for node in ast.walk(tree):
            if count >= max_functions:
                break
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                has_docstring = ast.get_docstring(node) is not None
                if has_docstring:
                    continue
                start, end = node.lineno, getattr(node, "end_lineno", node.lineno)
                text = "\n".join(lines[start - 1:end])
                from .embeddings import Chunk
                chunk = Chunk(pf.path, start, end, text, symbol_name=node.name)
                docstring = generate_function_docstring(chunk, api_key=api_key)
                results.append({
                    "file_path": pf.path, "symbol_name": node.name,
                    "line": start, "generated_docstring": docstring,
                })
                count += 1
    return results
