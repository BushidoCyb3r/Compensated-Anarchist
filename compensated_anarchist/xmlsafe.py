"""Parse XML that came from outside (scanner output, network maps the analyst drops in, documents) safely.

Entity declarations are what "billion laughs" (exponential expansion) and external-entity attacks need, and none of
the formats we read (nmap XML, draw.io / Visio, Office XML) uses them, so a document declaring any is refused before
it reaches the parser. Recent expat already limits expansion; this does not depend on the host's expat version.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

_ENTITY = re.compile(r"<!ENTITY", re.IGNORECASE)


def _text(data: bytes | str) -> str:
    if isinstance(data, str):
        return data
    for bom, enc in ((b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"), (b"\xef\xbb\xbf", "utf-8-sig")):
        if data.startswith(bom):
            return data.decode(enc, errors="replace")
    if len(data) > 1 and (data[0] == 0 or data[1] == 0):  # UTF-16 without a byte-order mark
        return data.decode("utf-16-be" if data[0] == 0 else "utf-16-le", errors="replace")
    return data.decode("utf-8", errors="replace")


def fromstring(data: bytes | str) -> ET.Element:
    if _ENTITY.search(_text(data)):
        raise ValueError("refused: the XML declares entities (<!ENTITY>), which is how entity-expansion and "
                         "external-entity attacks work; none of the formats we read needs them")
    return ET.fromstring(data)
