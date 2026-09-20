"""Domain profiles built on the generic record schema.

A profile supplies a :class:`~ledgerguard.schema.RecordSchema` and the domain
rules that make a verification finding interpretable in the language of that
domain. The layers below -- canonicalisation, Merkle, commitments, backends,
verification -- import nothing from here; the dependency runs one way only.

Two profiles ship, and the second exists to keep the first honest: a layer
with one client always looks general.
"""

from __future__ import annotations

from ..schema import RecordSchema
from .accounting import JOURNAL_ENTRY_V1
from .provenance import INSTRUMENT_EVENT_V1

#: Profiles addressable by name, for command-line tools and configuration.
PROFILES: dict[str, RecordSchema] = {
    "accounting": JOURNAL_ENTRY_V1,
    "provenance": INSTRUMENT_EVENT_V1,
}


def get_profile(name: str) -> RecordSchema:
    """Look up a schema by profile name.

    Raises:
        KeyError: no such profile.
    """
    try:
        return PROFILES[name]
    except KeyError:
        known = ", ".join(sorted(PROFILES))
        raise KeyError(f"unknown profile {name!r}; available: {known}") from None


def profile_names() -> tuple[str, ...]:
    return tuple(sorted(PROFILES))


__all__ = [
    "INSTRUMENT_EVENT_V1",
    "JOURNAL_ENTRY_V1",
    "PROFILES",
    "get_profile",
    "profile_names",
]
