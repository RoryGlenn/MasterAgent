"""Immutable snapshots of operator-selected TLS trust stores."""

from __future__ import annotations

import hashlib
import os
import ssl
import stat
from dataclasses import dataclass, field
from pathlib import Path

from master_agent.errors import ConfigurationError

_MAX_CA_BUNDLE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CaBundleSnapshot:
    """Safely opened CA bytes and the identity of their canonical path."""

    path: Path
    data: bytes = field(repr=False)
    sha256: str


def capture_ca_bundle(path: Path) -> CaBundleSnapshot:
    """Capture one stable, bounded regular file without following its final link."""

    try:
        resolved = path.expanduser().resolve(strict=True)
        path_metadata = resolved.lstat()
        if not stat.S_ISREG(path_metadata.st_mode):
            raise ConfigurationError("connector CA bundle must be a regular file")

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(resolved, flags)
        try:
            opened_metadata = os.fstat(descriptor)
            if not _same_file(path_metadata, opened_metadata):
                raise ConfigurationError(
                    "connector CA bundle changed during snapshot capture"
                )
            blocks: list[bytes] = []
            total = 0
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > _MAX_CA_BUNDLE_BYTES:
                    raise ConfigurationError(
                        "connector CA bundle exceeds the 4 MiB safety limit"
                    )
                blocks.append(block)
            final_metadata = os.fstat(descriptor)
        finally:
            os.close(descriptor)

        current_metadata = resolved.lstat()
        if (
            not _same_file(opened_metadata, final_metadata)
            or not _same_file(final_metadata, current_metadata)
            or total != opened_metadata.st_size
            or final_metadata.st_size != opened_metadata.st_size
            or final_metadata.st_mtime_ns != opened_metadata.st_mtime_ns
            or final_metadata.st_ctime_ns != opened_metadata.st_ctime_ns
        ):
            raise ConfigurationError(
                "connector CA bundle changed during snapshot capture"
            )
        data = b"".join(blocks)
        return CaBundleSnapshot(
            path=resolved,
            data=data,
            sha256=hashlib.sha256(data).hexdigest(),
        )
    except ConfigurationError:
        raise
    except OSError as error:
        raise ConfigurationError(
            "connector CA bundle could not be captured safely"
        ) from error


def create_ssl_context(ca_bundle_data: bytes | None) -> ssl.SSLContext:
    """Create TLS trust from immutable captured certificate data."""

    if ca_bundle_data is None:
        return ssl.create_default_context()
    try:
        try:
            certificate_data: str | bytes = ca_bundle_data.decode("ascii")
        except UnicodeDecodeError:
            certificate_data = ca_bundle_data
        return ssl.create_default_context(cadata=certificate_data)
    except (ValueError, ssl.SSLError) as error:
        raise ConfigurationError(
            "connector CA bundle is not valid certificate data"
        ) from error


def _same_file(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        stat.S_ISREG(first.st_mode)
        and stat.S_ISREG(second.st_mode)
        and first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
    )
