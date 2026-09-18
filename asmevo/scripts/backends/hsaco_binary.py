"""Strict capability declaration for the deferred HSACO binary backend."""

from __future__ import annotations

from .common import V2_BINARY_CAPABILITIES

REQUIRED_CAPABILITIES = frozenset(V2_BINARY_CAPABILITIES)

# A project may only enable this backend after its preflight independently proves
# deterministic round-trip and native replay.  The generic skill deliberately
# does not contain a universal HSACO recovery implementation.
REQUIRES_BINARY_ROUNDTRIP = True
