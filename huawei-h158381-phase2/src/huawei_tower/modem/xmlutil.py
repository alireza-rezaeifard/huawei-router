from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from .errors import ModemParseError


def parse_xml(text: str) -> ET.Element:
    """Parse a modem XML response and fail closed on malformed content."""
    try:
        return ET.fromstring(text)
    except (ET.ParseError, ValueError) as exc:
        raise ModemParseError("Modem returned malformed XML") from exc


def child_text(root: ET.Element, tag: str, default: str | None = None) -> str | None:
    node = root.find(tag)
    if node is None or node.text is None:
        return default
    return node.text.strip()


def element_to_dict(root: ET.Element) -> dict[str, Any]:
    """Convert simple XML to a dictionary; repeated tags become lists."""
    result: dict[str, Any] = {}
    for child in root:
        value: Any = element_to_dict(child) if len(child) else (child.text or "").strip()
        if child.tag in result:
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(value)
        else:
            result[child.tag] = value
    return result
