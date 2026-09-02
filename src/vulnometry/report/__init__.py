"""Output surfaces: terminal, Excel workbook, HTML dashboard, JSON, Markdown."""

from .console import render_one, render_table, to_csv, to_json, to_markdown  # noqa: F401
from .dashboard import build_dashboard  # noqa: F401
from .workbook import build_workbook  # noqa: F401

__all__ = [
    "render_one", "render_table", "to_json", "to_markdown", "to_csv",
    "build_workbook", "build_dashboard",
]
