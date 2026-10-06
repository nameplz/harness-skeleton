"""Extract GitHub expressions without treating quoted delimiters as syntax."""

from __future__ import annotations


def extract_github_expressions(value: str) -> tuple[list[tuple[str, str]], bool]:
    """Return expression source, code without string literals, and malformed state."""
    expressions: list[tuple[str, str]] = []
    cursor = 0
    malformed = False
    while (start := value.find("${{", cursor)) != -1:
        index = start + 3
        source: list[str] = []
        code: list[str] = []
        quoted = False
        closed = False
        while index < len(value):
            char = value[index]
            if quoted:
                if char == "'":
                    if index + 1 < len(value) and value[index + 1] == "'":
                        source.extend((char, char))
                        index += 2
                        continue
                    quoted = False
                source.append(char)
                index += 1
                continue
            if char == "'":
                quoted = True
                source.append(char)
                index += 1
                continue
            if value.startswith("}}", index):
                expressions.append(("".join(source).strip(), "".join(code).strip()))
                cursor = index + 2
                closed = True
                break
            source.append(char)
            code.append(char)
            index += 1
        if not closed:
            malformed = True
            break
    return expressions, malformed
