"""
analyzer.py — Static analysis: cyclomatic complexity, maintainability index,
and a tech-debt hour estimate. Uses `radon` for Python (real AST-based metrics,
not LLM guesswork). Non-Python languages fall back to a lightweight heuristic
(line-length/nesting-based complexity proxy) so the tool still works on
mixed-language repos.
"""

from dataclasses import dataclass, field
from radon.complexity import cc_visit
from radon.metrics import mi_visit
from radon.raw import analyze as raw_analyze

from .ingestion import ProjectMap, ProjectFile


@dataclass
class FileMetric:
    path: str
    language: str
    loc: int
    complexity: float          # average cyclomatic complexity of functions in file
    maintainability_index: float  # 0-100, higher is better
    function_count: int
    functions: list = field(default_factory=list)  # [{name, complexity, lineno}]


@dataclass
class AnalysisResult:
    file_metrics: list[FileMetric] = field(default_factory=list)
    total_files: int = 0
    total_loc: int = 0
    avg_complexity: float = 0.0
    avg_maintainability: float = 0.0
    tech_debt_hours: float = 0.0
    hotspots: list = field(default_factory=list)  # worst files by complexity


# Rough industry heuristic: minutes of remediation per complexity point above
# threshold, plus a fixed penalty for low maintainability. This is intentionally
# simple and transparent (unlike a black-box "debt score") so it can be
# explained in an interview.
COMPLEXITY_THRESHOLD = 10
MIN_MAINTAINABILITY = 65
MINUTES_PER_EXCESS_COMPLEXITY_POINT = 12
MINUTES_PER_MI_POINT_BELOW_THRESHOLD = 4


def analyze_project(pm: ProjectMap) -> AnalysisResult:
    result = AnalysisResult()

    for pf in pm.files:
        if pf.language == "Python":
            fm = _analyze_python_file(pf)
        else:
            fm = _analyze_generic_file(pf)
        if fm:
            result.file_metrics.append(fm)

    result.total_files = len(result.file_metrics)
    result.total_loc = sum(fm.loc for fm in result.file_metrics)

    if result.file_metrics:
        result.avg_complexity = round(
            sum(fm.complexity for fm in result.file_metrics) / len(result.file_metrics), 2
        )
        result.avg_maintainability = round(
            sum(fm.maintainability_index for fm in result.file_metrics) / len(result.file_metrics), 2
        )

    result.tech_debt_hours = round(_estimate_tech_debt(result.file_metrics), 1)
    result.hotspots = sorted(
        result.file_metrics, key=lambda fm: (fm.complexity, -fm.maintainability_index), reverse=True
    )[:10]

    return result


def _analyze_python_file(pf: ProjectFile) -> FileMetric | None:
    try:
        with open(pf.abs_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
    except OSError:
        return None

    try:
        blocks = cc_visit(source)
    except Exception:
        blocks = []

    functions = [{"name": b.name, "complexity": b.complexity, "lineno": b.lineno} for b in blocks]
    avg_cc = round(sum(b.complexity for b in blocks) / len(blocks), 2) if blocks else 1.0

    try:
        mi = round(mi_visit(source, multi=True), 2)
    except Exception:
        mi = 100.0

    try:
        raw = raw_analyze(source)
        loc = raw.loc
    except Exception:
        loc = pf.loc

    return FileMetric(
        path=pf.path, language=pf.language, loc=loc, complexity=avg_cc,
        maintainability_index=mi, function_count=len(blocks), functions=functions,
    )


def _analyze_generic_file(pf: ProjectFile) -> FileMetric | None:
    """Heuristic complexity for non-Python files: count of branching keywords
    and average nesting depth per LOC, scaled to look like a CC-style number."""
    branch_keywords = (
        "if ", "else", "for ", "while ", "case ", "catch", "&&", "||", "switch",
    )
    try:
        with open(pf.abs_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return None

    branch_count = sum(1 for line in lines for kw in branch_keywords if kw in line)
    max_indent = 0
    for line in lines:
        stripped = line.lstrip()
        if not stripped:
            continue
        indent = (len(line) - len(stripped)) // 2
        max_indent = max(max_indent, indent)

    approx_cc = 1 + branch_count
    # Fake an MI-like score: penalize high branch density and deep nesting
    density = branch_count / max(pf.loc, 1)
    mi_approx = max(0.0, 100 - (density * 150) - (max_indent * 2))

    return FileMetric(
        path=pf.path, language=pf.language, loc=pf.loc,
        complexity=round(approx_cc, 2), maintainability_index=round(mi_approx, 2),
        function_count=0, functions=[],
    )


def _estimate_tech_debt(file_metrics: list[FileMetric]) -> float:
    total_minutes = 0.0
    for fm in file_metrics:
        if fm.complexity > COMPLEXITY_THRESHOLD:
            total_minutes += (fm.complexity - COMPLEXITY_THRESHOLD) * MINUTES_PER_EXCESS_COMPLEXITY_POINT
        if fm.maintainability_index < MIN_MAINTAINABILITY:
            total_minutes += (MIN_MAINTAINABILITY - fm.maintainability_index) * MINUTES_PER_MI_POINT_BELOW_THRESHOLD
    return total_minutes / 60.0
