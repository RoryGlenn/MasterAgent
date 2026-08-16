"""Terminal-safe rendering regression tests."""

from __future__ import annotations

import unittest

from master_agent.terminal import render_terminal_text


class TerminalRenderingTests(unittest.TestCase):
    """Keep untrusted terminal fields inert, bounded, and readable."""

    def test_c0_c1_escape_osc_and_line_controls_become_visible(self) -> None:
        value = "prefix\x1b[31m\x9b32m\x1b]52;c;YQ==\x07\r\b\n\t\x85\u2028\u2029suffix"

        rendered = render_terminal_text(value)

        for control in (
            "\x1b",
            "\x9b",
            "\x07",
            "\r",
            "\b",
            "\n",
            "\t",
            "\x85",
            "\u2028",
            "\u2029",
        ):
            self.assertNotIn(control, rendered)
        for visible in (
            "\\u001b",
            "\\u009b",
            "\\u0007",
            "\\u000d",
            "\\u0008",
            "\\u000a",
            "\\u0009",
            "\\u0085",
            "\\u2028",
            "\\u2029",
        ):
            self.assertIn(visible, rendered)

    def test_bidirectional_formatting_controls_become_visible(self) -> None:
        controls = (
            "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
        )

        rendered = render_terminal_text(f"before{controls}after")

        self.assertEqual(
            rendered,
            "before"
            "\\u061c\\u200e\\u200f\\u202a\\u202b\\u202c"
            "\\u202d\\u202e\\u2066\\u2067\\u2068\\u2069"
            "after",
        )

    def test_normal_unicode_remains_readable(self) -> None:
        value = "Café 東京 مرحبا 👩‍💻"

        self.assertEqual(render_terminal_text(value), value)

    def test_rendered_length_includes_escapes_and_truncation_marker(self) -> None:
        rendered = render_terminal_text("a" * 80 + "\x1b" * 20, max_characters=64)

        self.assertEqual(len(rendered), 64)
        self.assertTrue(rendered.endswith("…"))
        self.assertNotIn("\x1b", rendered)

    def test_invalid_limits_fail_closed(self) -> None:
        for invalid in (0, -1, True, 1.5):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                render_terminal_text("value", max_characters=invalid)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
