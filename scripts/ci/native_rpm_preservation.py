#!/usr/bin/env python3
"""Bounded RPM v4 framing and exact signed-content preservation.

This comparison does not authenticate a package or interpret its metadata. A
caller must still verify the native signature and package identity independently.
Only signature-header bytes and their canonical zero padding may change.
Format: https://rpm.org/docs/4.20.x/manual/format_v4.html
Regions: https://rpm.org/docs/4.20.x/manual/format_header.html
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import asdict, dataclass

MAX_PACKAGE_BYTES = 256 * 1024 * 1024
MAX_HEADER_INDEXES = 4096
MAX_HEADER_DATA_BYTES = 16 * 1024 * 1024
HEADER_MAGIC = bytes.fromhex("8eade80100000000")


class RPMPreservationError(ValueError):
    """The input is outside the supported RPM framing or changed content."""


@dataclass(frozen=True)
class RPMContent:
    """Digests of actual bytes, not claims read from RPM signature tags."""

    lead_sha256: str
    main_header_sha256: str
    main_header_size: int
    compressed_payload_sha256: str
    compressed_payload_size: int

    def document(self) -> dict[str, str | int]:
        return asdict(self)


def _header_end(data: bytes, start: int, region: int) -> int:
    if start < 0 or start > len(data) - 16 or data[start:start + 8] != HEADER_MAGIC:
        raise RPMPreservationError("RPM header intro is truncated or unsupported")
    indexes, length = struct.unpack_from(">II", data, start + 8)
    if not 1 <= indexes <= MAX_HEADER_INDEXES or not 16 <= length <= MAX_HEADER_DATA_BYTES:
        raise RPMPreservationError("RPM header index or data exceeds supported bounds")
    data_start = start + 16 + indexes * 16
    end = data_start + length
    if end > len(data):
        raise RPMPreservationError("RPM header index or data is truncated")
    # Reject dribbles and overlapping region boundaries. Only a complete on-disk
    # immutable region is accepted; installed RPM database headers are not input.
    if struct.unpack_from(">IIII", data, start + 16) != (region, 7, length - 16, 16):
        raise RPMPreservationError("RPM header has no exact immutable region")
    if struct.unpack_from(">IIiI", data, end - 16) != (region, 7, -indexes * 16, 16):
        raise RPMPreservationError("RPM immutable region trailer is inconsistent")
    previous_tag = region
    for position in range(1, indexes):
        tag, kind, offset, count = struct.unpack_from(">IIII", data, start + 16 + position * 16)
        if tag < 100 or tag <= previous_tag or not 1 <= kind <= 9 or not 0 < count <= length:
            raise RPMPreservationError("RPM header index entry is unsupported")
        if offset >= length - 16:
            raise RPMPreservationError("RPM value starts outside its immutable data region")
        previous_tag = tag
    # Typed metadata, value extents and payload validity are the native reader's
    # responsibility. No semantic value is trusted or returned by this parser.
    return end


def inspect_content(data: bytes) -> RPMContent:
    """Fingerprint the lead, whole main header and compressed payload in place.

    All reads are bounds checked. No decompression, subprocess, file extraction
    or package scripts run here. Memory views avoid copying the package payload.
    """
    if not isinstance(data, bytes) or not 96 <= len(data) <= MAX_PACKAGE_BYTES:
        raise RPMPreservationError("RPM package size or input type is unsupported")
    if data[:6] != bytes.fromhex("edabeedb0300") or data[6:8] != b"\0\0" or data[78:80] != b"\0\5":
        raise RPMPreservationError("RPM lead is not a supported v4 binary package")
    signature_end = _header_end(data, 96, 62)
    main_start = (signature_end + 7) & ~7
    if main_start > len(data) or any(data[signature_end:main_start]):
        raise RPMPreservationError("RPM signature padding is truncated or nonzero")
    main_end = _header_end(data, main_start, 63)
    if main_end >= len(data):
        raise RPMPreservationError("RPM compressed payload is empty")
    view = memoryview(data)
    return RPMContent(
        hashlib.sha256(view[:96]).hexdigest(),
        hashlib.sha256(view[main_start:main_end]).hexdigest(), main_end - main_start,
        hashlib.sha256(view[main_end:]).hexdigest(), len(data) - main_end,
    )


def require_preserved(unsigned: RPMContent, signed: RPMContent) -> None:
    """Require every observed byte region and size outside signatures to match."""
    if type(unsigned) is not RPMContent or type(signed) is not RPMContent or unsigned != signed:
        raise RPMPreservationError("RPM signing changed the lead, main header or compressed payload")
