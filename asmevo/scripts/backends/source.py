"""Source-backend declarations for launch, HIP, and Triton surfaces."""

from __future__ import annotations

from .common import V2_SOURCE_CAPABILITIES

SURFACES = {"launch_config", "hip_source", "triton_source"}
REQUIRED_CAPABILITIES = frozenset(V2_SOURCE_CAPABILITIES)
