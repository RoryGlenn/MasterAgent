"""Bounded terminal rendering for untrusted diagnostic text."""

from __future__ import annotations

MAX_TERMINAL_FIELD_CHARACTERS = 1_024
MAX_TERMINAL_EXCERPT_CHARACTERS = 240

_BIDI_FORMATTING_CONTROLS = frozenset(
    {
        "\u061c",  # Arabic letter mark
        "\u200e",  # Left-to-right mark
        "\u200f",  # Right-to-left mark
        "\u202a",  # Left-to-right embedding
        "\u202b",  # Right-to-left embedding
        "\u202c",  # Pop directional formatting
        "\u202d",  # Left-to-right override
        "\u202e",  # Right-to-left override
        "\u2066",  # Left-to-right isolate
        "\u2067",  # Right-to-left isolate
        "\u2068",  # First strong isolate
        "\u2069",  # Pop directional isolate
    }
)
_UNICODE_LINE_CONTROLS = frozenset({"\u2028", "\u2029"})


def render_terminal_text(
    value: str,
    *,
    max_characters: int = MAX_TERMINAL_FIELD_CHARACTERS,
) -> str:
    """Render untrusted text as one inert, length-bounded terminal field.

    C0, DEL, C1, surrogate, Unicode line/paragraph separator, and
    bidirectional formatting characters become visible ``\\uXXXX`` tokens.
    All other Unicode remains readable. The returned string never exceeds the
    requested number of Python characters, including its truncation marker.
    """

    if not isinstance(value, str):
        raise TypeError("terminal text must be a string")
    if (
        isinstance(max_characters, bool)
        or not isinstance(max_characters, int)
        or max_characters <= 0
    ):
        raise ValueError("terminal text limit must be a positive integer")

    rendered: list[str] = []
    rendered_characters = 0
    truncated = False
    for character in value:
        unit = _render_character(character)
        if rendered_characters + len(unit) > max_characters:
            truncated = True
            break
        rendered.append(unit)
        rendered_characters += len(unit)

    if not truncated:
        return "".join(rendered)

    while rendered and rendered_characters >= max_characters:
        removed = rendered.pop()
        rendered_characters -= len(removed)
    rendered.append("…")
    return "".join(rendered)


def _render_character(character: str) -> str:
    codepoint = ord(character)
    if (
        codepoint <= 0x1F
        or 0x7F <= codepoint <= 0x9F
        or 0xD800 <= codepoint <= 0xDFFF
        or character in _BIDI_FORMATTING_CONTROLS
        or character in _UNICODE_LINE_CONTROLS
    ):
        return f"\\u{codepoint:04x}"
    return character
