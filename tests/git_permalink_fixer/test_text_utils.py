import pytest
from git_permalink_fixer.text_utils import parse_tolerance_input


def test_parse_tolerance_input_valid_percentage():
    assert parse_tolerance_input("50%") == (True, 50)
    # Not intentional to support "50 %" but that's how it was coded by AI and it doesn't hurt
    assert parse_tolerance_input("50 %") == (True, 50)
    assert parse_tolerance_input("0%") == (True, 0)
    assert parse_tolerance_input("100%") == (True, 100)


def test_parse_tolerance_input_invalid_percentage_value():
    with pytest.raises(ValueError, match="Percentage tolerance must be between 0% and 100%"):
        parse_tolerance_input("101%")
    with pytest.raises(ValueError, match="Percentage tolerance must be between 0% and 100%"):
        parse_tolerance_input("-1%")


def test_parse_tolerance_input_invalid_percentage_format():
    with pytest.raises(ValueError, match="Invalid percentage tolerance format 'abc%'"):
        parse_tolerance_input("abc%")
    with pytest.raises(ValueError, match="Invalid percentage tolerance format '%'"):
        parse_tolerance_input("%")


def test_parse_tolerance_input_valid_absolute():
    assert parse_tolerance_input("10") == (False, 10)
    assert parse_tolerance_input("0") == (False, 0)


def test_parse_tolerance_input_invalid_absolute_value():
    with pytest.raises(ValueError, match="Absolute line shift tolerance cannot be negative."):
        parse_tolerance_input("-5")


def test_parse_tolerance_input_invalid_absolute_format():
    with pytest.raises(ValueError, match="Invalid absolute tolerance format 'xyz'"):
        parse_tolerance_input("xyz")
