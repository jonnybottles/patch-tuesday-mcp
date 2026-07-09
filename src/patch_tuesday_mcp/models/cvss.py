"""CVSS vector parsing.

Parses CVSS v3.x vector strings (e.g.
``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``) into their base-metric
components. Parsing is deliberately lenient: unknown or malformed input yields
``None`` (or drops the offending metric) rather than raising, so a bad vector
never breaks a search. The raw vector string is always preserved by the caller.
"""

from pydantic import BaseModel

# Base-metric abbreviation -> the field it populates on CvssVector.
_BASE_METRICS = {
    "AV": "attack_vector",
    "AC": "attack_complexity",
    "PR": "privileges_required",
    "UI": "user_interaction",
    "S": "scope",
    "C": "confidentiality",
    "I": "integrity",
    "A": "availability",
}

# Allowed single-letter values per base metric (CVSS v3.x).
_ALLOWED_VALUES = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"N", "L", "H"},
    "I": {"N", "L", "H"},
    "A": {"N", "L", "H"},
}


class CvssVector(BaseModel):
    """Structured CVSS v3.x base-metric components.

    Values use the canonical single-letter CVSS codes (e.g. ``attack_vector``
    is one of ``N``/``A``/``L``/``P``). Any metric absent from the source vector
    is left as ``None``.
    """

    version: str | None = None
    attack_vector: str | None = None
    attack_complexity: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    scope: str | None = None
    confidentiality: str | None = None
    integrity: str | None = None
    availability: str | None = None

    def to_dict(self) -> dict:
        """Compact dict of the populated components (drops unset fields)."""
        return self.model_dump(exclude_none=True)


def parse_cvss_vector(vector: str | None) -> CvssVector | None:
    """Parse a CVSS v3.x vector string into a :class:`CvssVector`.

    Returns ``None`` for empty, non-v3, or otherwise unparseable input, and
    ignores unrecognized or out-of-range metrics instead of raising. A vector
    that yields no recognized base metrics is treated as unparseable.
    """
    if not vector or not isinstance(vector, str):
        return None

    parts = [p for p in vector.strip().split("/") if p]
    if not parts:
        return None

    version: str | None = None
    head = parts[0]
    if head.upper().startswith("CVSS:"):
        version = head.split(":", 1)[1].strip() or None
        parts = parts[1:]

    # Require an explicit CVSS v3.x version prefix. MSRC vectors always carry
    # one; without it we cannot tell v2/v3/v4 apart, so fail open to None.
    if version is None or not version.startswith("3."):
        return None

    fields: dict[str, str] = {}
    for part in parts:
        metric, sep, value = part.partition(":")
        if not sep:
            continue
        metric = metric.strip().upper()
        value = value.strip().upper()
        field = _BASE_METRICS.get(metric)
        if field is None:
            continue  # temporal/environmental/unknown metric — ignore
        if value not in _ALLOWED_VALUES[metric]:
            continue  # malformed value — drop this metric, keep the rest
        fields[field] = value

    if not fields:
        return None

    return CvssVector(version=version, **fields)
