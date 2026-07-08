from __future__ import annotations

from typing import Callable

from .._fingerprint import Fingerprint
from . import chrome_131, chrome_142, chrome_146, chrome_148, chrome_150, chrome_stable

_REGISTRY: dict[str, Callable[[], Fingerprint]] = {
    "chrome:131": chrome_131.build,
    "chrome:142": chrome_142.build,
    "chrome:146": chrome_146.build,
    "chrome:148": chrome_148.build,
    "chrome:150": chrome_150.build,
    "chrome:stable": chrome_stable.build,
}


def get(name: str) -> Fingerprint:
    """Look up a preset by name. Raises :class:`ValueError` if unknown."""
    try:
        factory = _REGISTRY[name]
    except KeyError:
        raise ValueError(f"unknown preset {name!r}; known: {sorted(_REGISTRY)}") from None
    return factory()


def names() -> list[str]:
    """Return all known preset names, sorted."""
    return sorted(_REGISTRY)
