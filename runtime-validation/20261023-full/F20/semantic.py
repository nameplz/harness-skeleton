import pytest

raise SystemExit(pytest.main([
    "-q",
    "-p",
    "no:cacheprovider",
    "tests/test_harness_compatibility.py::test_slash_screen_exception_is_narrow",
]))
