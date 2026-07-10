"""Local product profiles (watchlists) for ``msrc_search``.

A *profile* is a named set of product-name matchers and product-family matchers
used to narrow a search to the products an organization actually runs. Matching
happens entirely locally against each vulnerability's ``affected_products`` and
``product_families``; profile contents are never transmitted to MSRC,
FIRST.org, CISA, or telemetry.

Built-in defaults cover common identity/security triage groupings. Operators can
override or extend them by pointing ``MSRC_PROFILES_PATH`` at a JSON file:

    {
      "identity-core": {
        "families": ["Windows", "Azure"],
        "products": ["Microsoft Exchange Server", "Microsoft Entra"]
      }
    }

Each profile entry may contain ``products`` and/or ``families`` (both optional
lists of case-insensitive partial-match strings). File profiles are merged over
the built-ins, so a file entry with the same name replaces the built-in.
"""

import json
import os

# Built-in profiles for identity/security triage. Product matchers are partial,
# case-insensitive substrings tested against affected product names; family
# matchers are tested against MSRC product-family labels.
BUILTIN_PROFILES: dict[str, dict[str, list[str]]] = {
    "identity-core": {
        "families": ["Windows", "Azure"],
        "products": [
            "Windows Server",
            "Exchange Server",
            "Microsoft Entra",
            "Microsoft Intune",
            "Microsoft Defender",
            "Microsoft Edge",
        ],
    },
    "endpoint": {
        "families": ["Browser"],
        "products": [
            "Windows",
            "Microsoft Defender",
            "Microsoft Intune",
            "Microsoft Edge",
        ],
    },
    "server-infrastructure": {
        "families": ["Windows", "ESU"],
        "products": [
            "Windows Server",
            "Exchange Server",
            "SharePoint",
            "SQL Server",
        ],
    },
}


class ProfileError(ValueError):
    """Raised when a profile is unknown or the profile config is invalid.

    Surfaced to the caller as a local ``invalid_input`` error rather than
    silently falling back to a broad, unfiltered search (which would defeat the
    point of a watchlist and could over-disclose).
    """


def _validate_profiles(data: object, source: str) -> dict[str, dict[str, list[str]]]:
    if not isinstance(data, dict):
        raise ProfileError(f"Profile config in {source} must be a JSON object of name -> profile.")
    result: dict[str, dict[str, list[str]]] = {}
    for name, entry in data.items():
        if not isinstance(entry, dict):
            raise ProfileError(f"Profile {name!r} in {source} must be an object.")
        products = entry.get("products", [])
        families = entry.get("families", [])
        for label, value in (("products", products), ("families", families)):
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise ProfileError(
                    f"Profile {name!r} field {label!r} in {source} must be a list of strings."
                )
        if not products and not families:
            raise ProfileError(
                f"Profile {name!r} in {source} must define at least one product or family."
            )
        result[name] = {"products": list(products), "families": list(families)}
    return result


def _load_file_profiles() -> dict[str, dict[str, list[str]]]:
    path = os.getenv("MSRC_PROFILES_PATH")
    if not path:
        return {}
    if not os.path.isfile(path):
        raise ProfileError(f"MSRC_PROFILES_PATH points to a missing file: {path}")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileError(f"Could not read profile config {path}: {exc}") from exc
    return _validate_profiles(data, path)


def load_profiles() -> dict[str, dict[str, list[str]]]:
    """Return all known profiles (built-ins plus any file overrides).

    Raises ``ProfileError`` if ``MSRC_PROFILES_PATH`` is set but missing or
    invalid, so a misconfiguration surfaces as a clear error.
    """
    profiles = {name: {"products": list(p["products"]), "families": list(p["families"])}
                for name, p in BUILTIN_PROFILES.items()}
    profiles.update(_load_file_profiles())
    return profiles


def resolve_profile(name: str) -> tuple[list[str], list[str]]:
    """Resolve a profile name to its ``(products, families)`` matcher lists.

    Case-insensitive on the name. Raises ``ProfileError`` for an unknown name
    or invalid config, listing the available profiles.
    """
    profiles = load_profiles()
    key = name.strip().lower()
    for candidate, entry in profiles.items():
        if candidate.lower() == key:
            return list(entry["products"]), list(entry["families"])
    available = ", ".join(sorted(profiles)) or "(none configured)"
    raise ProfileError(f"Unknown product_profile: {name!r}. Available profiles: {available}.")
