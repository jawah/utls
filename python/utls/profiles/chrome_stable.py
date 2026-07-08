"""Alias module: ``chrome:stable`` points to the current Chrome stable preset.

Updating this file is the one-line cutover when a new Chrome stable ships:
swap the import and the changelog entry, leave everything else alone.

Currently aliased to: :mod:`utls.profiles.chrome_150` (Chrome 150.x stable,
July 2026). Captured against ``tls.peet.ws`` from a live Chrome 150
incognito tab.
"""

from __future__ import annotations

from . import chrome_150 as _current

build = _current.build
HTTP_HEADERS = _current.HTTP_HEADERS
