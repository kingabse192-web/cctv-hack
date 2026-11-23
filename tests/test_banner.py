from absearch.banner import banner_lines, banner_text


def test_banner_is_six_rows_and_aligned():
    lines = banner_lines()
    assert len(lines) == 6
    assert len({len(line) for line in lines}) == 1


def test_banner_renders_ab_search_wordmark():
    text = banner_text()
    assert len(text.splitlines()) == 6
    assert "█" in text
    assert "╗" in text
    assert banner_lines("AB")[0] != banner_lines("AB SEARCH")[0]
