"""Edge-case tests for the markdown/CSV triage renderers."""

from patch_tuesday_mcp.models.vulnerability import Vulnerability
from patch_tuesday_mcp.tools import formatters


def test_md_cell_escapes_pipes_and_newlines():
    v = Vulnerability(cve="CVE-2026-1", title="Bad | title\nwith newline", severity="Low")
    md = formatters.render_markdown([v], {"month": "2026-Jun", "title": "T"}, 1)
    assert "Bad \\| title with newline" in md


def test_render_markdown_empty_page():
    md = formatters.render_markdown([], {"month": "2026-Jun", "title": "T"}, 0)
    assert "**0** vulnerabilities matched" in md
    assert md.count("|") > 0, "table header still renders"


def test_render_csv_quotes_commas_and_quotes():
    v = Vulnerability(cve="CVE-2026-1", title='has,comma and "quote"', severity="Low")
    out = formatters.render_csv([v])
    assert '"has,comma and ""quote"""' in out
    assert out.splitlines()[0] == ",".join(formatters.TRIAGE_COLUMNS)
