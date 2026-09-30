from tools.coverage_report import OUT_DIR, render_layer, render_markdown, rows


def test_all_rules_are_verified():
    assert all(r["verified"] for r in rows())


def test_coverage_markdown_is_current():
    assert (OUT_DIR / "coverage.md").read_text() == render_markdown(), \
        "run: python3 -m tools.coverage_report"


def test_navigator_layer_is_current():
    assert (OUT_DIR / "navigator_layer.json").read_text() == render_layer(), \
        "run: python3 -m tools.coverage_report"
