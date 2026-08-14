"""Safe text normalization utilities for retrieved documents."""

from __future__ import annotations

from html import unescape
from html.parser import HTMLParser
import re


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() in {"br", "p", "div", "li", "tr", "h1", "h2", "h3"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"p", "div", "li", "tr", "h1", "h2", "h3"}:
            self.parts.append("\n")


def html_to_text(value: str) -> str:
    """Convert HTML storage content into normalized plain text.

    Parameters
    ----------
    value
        HTML or HTML-like text.

    Returns
    -------
    str
        Plain text with compact whitespace.
    """

    parser = _TextExtractor()
    try:
        parser.feed(value)
        parser.close()
        rendered = "".join(parser.parts)
    except Exception:
        rendered = re.sub(r"<[^>]+>", " ", value)
    rendered = unescape(rendered)
    lines = [" ".join(line.split()) for line in rendered.splitlines()]
    return "\n".join(line for line in lines if line).strip()


def excerpt(value: str, limit: int = 500) -> str:
    """Return a compact bounded excerpt."""

    compact = " ".join(value.split())
    if len(compact) <= limit:
        return compact
    return compact[: max(0, limit - 1)].rstrip() + "…"
