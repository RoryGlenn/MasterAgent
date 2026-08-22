"""Descriptor-pinned boundaries for approved runtime directories."""

from __future__ import annotations

import os
import stat
import weakref
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Self, cast

from master_agent.errors import ConfigurationError
from master_agent.platform_runtime import (
    FilesystemObjectKind,
    PlatformObjectIdentity,
    get_secure_filesystem_backend,
)

_MAX_DIRECTORY_DEPTH = 64
_MINIMUM_INHERITED_DESCRIPTOR = 3


@dataclass(frozen=True, slots=True)
class DirectoryIdentity:
    """Stable identity and authorization metadata for one directory."""

    device: int
    inode: int
    owner: int
    mode: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> DirectoryIdentity:
        """Capture identity fields that must remain stable while pinned."""

        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            owner=value.st_uid,
            mode=stat.S_IMODE(value.st_mode),
        )

    def matches(self, value: os.stat_result) -> bool:
        """Return whether a fresh stat still represents this directory."""

        return stat.S_ISDIR(value.st_mode) and self == self.from_stat(value)

    def to_dict(self) -> dict[str, int]:
        """Return a JSON-compatible execution-binding representation."""

        return {
            "device": self.device,
            "inode": self.inode,
            "owner": self.owner,
            "mode": self.mode,
        }

    def to_platform_object_identity(self) -> PlatformObjectIdentity:
        """Return the exact versioned POSIX approval identity."""

        return PlatformObjectIdentity.from_posix(
            kind=FilesystemObjectKind.DIRECTORY,
            device=self.device,
            inode=self.inode,
            owner=self.owner,
            mode=self.mode,
        )


class PinnedDirectory:
    """Own a validated descriptor chain to one private runtime directory.

    The requested path is canonicalized once, then every component of that
    canonical path is opened relative to the already-open parent with
    ``O_DIRECTORY`` and ``O_NOFOLLOW``. Retaining the complete chain permits
    later validation without traversing a replaced ancestor pathname.

    Runtime roots must already exist before approval. The retained ``create``
    parameters are compatibility shims that fail closed instead of mutating a
    namespace before or after approval.
    """

    def __init__(
        self,
        *,
        path: Path,
        descriptors: tuple[int, ...],
        names: tuple[str | None, ...],
        identities: tuple[DirectoryIdentity, ...],
        require_private: bool,
    ) -> None:
        if not descriptors or not (len(descriptors) == len(names) == len(identities)):
            raise ValueError("pinned directory descriptor chain is invalid")
        self._path = path
        self._descriptors = descriptors
        self._names = names
        self._identities = identities
        self._require_private = require_private
        self._lock = RLock()
        self._finalizer = weakref.finalize(
            self,
            _close_descriptors,
            descriptors,
            self._lock,
        )

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        create: bool = False,
        mode: int = 0o700,
        expected_identity: DirectoryIdentity | PlatformObjectIdentity | None = None,
        require_private: bool = True,
    ) -> PinnedDirectory:
        """Open and pin one preexisting canonical directory path.

        Runtime write boundaries use the private default. Read-only callers may
        disable that permission policy only when they apply their own ownership
        policy to the pinned identity and every descriptor-relative child.
        """

        if create:
            raise ConfigurationError("runtime directories must exist before approval")
        if os.name == "nt":
            return cast(
                PinnedDirectory,
                _WindowsPinnedDirectory.open_native(
                    path,
                    expected_identity=expected_identity,
                    require_private=require_private,
                ),
            )
        get_secure_filesystem_backend()
        if isinstance(expected_identity, PlatformObjectIdentity):
            if expected_identity.platform != "posix":
                raise ConfigurationError(
                    "runtime directory identity platform differs from this host"
                )
            expected_identity = DirectoryIdentity(
                device=cast(int, expected_identity.device),
                inode=cast(int, expected_identity.inode),
                owner=cast(int, expected_identity.owner),
                mode=cast(int, expected_identity.mode),
            )
        selected = path.expanduser()
        if not selected.is_absolute():
            selected = Path.cwd() / selected
        canonical = selected.resolve(strict=False)
        components = canonical.parts[1:]
        if len(components) > _MAX_DIRECTORY_DEPTH:
            raise ConfigurationError("runtime directory path is too deep")
        descriptors: list[int] = []
        names: list[str | None] = []
        identities: list[DirectoryIdentity] = []
        try:
            root_descriptor = os.open(os.sep, _directory_open_flags())
            descriptors.append(root_descriptor)
            names.append(None)
            identities.append(_directory_identity(root_descriptor, private=False))
            for index, component in enumerate(components):
                descriptor = _open_directory_component(
                    descriptors[-1],
                    component,
                )
                descriptors.append(descriptor)
                names.append(component)
                identities.append(
                    _directory_identity(
                        descriptor,
                        private=require_private and index == len(components) - 1,
                    )
                )
                _validate_public_component(
                    descriptors[-2],
                    component,
                    identities[-1],
                )
            if not components and require_private:
                _validate_private_directory(os.fstat(root_descriptor))
            if expected_identity is not None and identities[-1] != expected_identity:
                raise ConfigurationError(
                    "runtime directory identity differs from the approved identity"
                )
            pinned = cls(
                path=canonical,
                descriptors=tuple(descriptors),
                names=tuple(names),
                identities=tuple(identities),
                require_private=require_private,
            )
            pinned.validate()
            return pinned
        except BaseException:
            _close_descriptor_values(descriptors)
            raise

    @property
    def path(self) -> Path:
        """Return the canonical display path bound to this descriptor chain."""

        return self._path

    @property
    def identity(self) -> DirectoryIdentity:
        """Return the final directory identity suitable for approval binding."""

        return self._identities[-1]

    @property
    def object_identity(self) -> PlatformObjectIdentity:
        """Return the exact versioned native identity for approval binding."""

        return self.identity.to_platform_object_identity()

    @property
    def closed(self) -> bool:
        """Return whether this object has released its descriptors."""

        return not self._finalizer.alive

    def fileno(self) -> int:
        """Return the borrowed final descriptor after validating the full chain."""

        self.validate()
        return self._descriptors[-1]

    def duplicate_fd(self) -> int:
        """Return a caller-owned duplicate of the validated final descriptor."""

        with self._lock:
            self.validate()
            descriptor = _duplicate_descriptor(self._descriptors[-1])
            try:
                if not self.identity.matches(os.fstat(descriptor)):
                    raise ConfigurationError(
                        "runtime directory changed while its descriptor was duplicated"
                    )
                return descriptor
            except BaseException:
                os.close(descriptor)
                raise

    def duplicate_descriptor_chain(self) -> tuple[int, ...]:
        """Return validated caller-owned descriptors from filesystem root to leaf."""

        with self._lock:
            self.validate()
            descriptors: list[int] = []
            try:
                for source, identity in zip(
                    self._descriptors,
                    self._identities,
                    strict=True,
                ):
                    descriptor = _duplicate_descriptor(source)
                    descriptors.append(descriptor)
                    if not identity.matches(os.fstat(descriptor)):
                        raise ConfigurationError(
                            "runtime directory changed while its descriptor chain "
                            "was duplicated"
                        )
                return tuple(descriptors)
            except BaseException:
                _close_descriptor_values(descriptors)
                raise

    def duplicate(self) -> PinnedDirectory:
        """Return an independently owned duplicate of the full descriptor chain."""

        with self._lock:
            self.validate()
            descriptors: list[int] = []
            try:
                for source, identity in zip(
                    self._descriptors,
                    self._identities,
                    strict=True,
                ):
                    descriptor = _duplicate_descriptor(source)
                    descriptors.append(descriptor)
                    if not identity.matches(os.fstat(descriptor)):
                        raise ConfigurationError(
                            "runtime directory changed while it was duplicated"
                        )
                return type(self)(
                    path=self._path,
                    descriptors=tuple(descriptors),
                    names=self._names,
                    identities=self._identities,
                    require_private=self._require_private,
                )
            except BaseException:
                _close_descriptor_values(descriptors)
                raise

    def pin_child(
        self,
        relative: Path | str,
        *,
        create: bool = False,
        mode: int = 0o700,
        expected_identity: DirectoryIdentity | PlatformObjectIdentity | None = None,
    ) -> PinnedDirectory:
        """Pin a bounded preexisting no-follow path beneath this one."""

        if create:
            raise ConfigurationError("runtime directories must exist before approval")
        if isinstance(expected_identity, PlatformObjectIdentity):
            if expected_identity.platform != "posix":
                raise ConfigurationError(
                    "runtime child identity platform differs from this host"
                )
            expected_identity = DirectoryIdentity(
                device=cast(int, expected_identity.device),
                inode=cast(int, expected_identity.inode),
                owner=cast(int, expected_identity.owner),
                mode=cast(int, expected_identity.mode),
            )
        child = Path(relative)
        if (
            child.is_absolute()
            or not child.parts
            or any(part in {"", ".", ".."} for part in child.parts)
        ):
            raise ConfigurationError(
                "runtime child directory must be a normalized relative path"
            )
        child_parts = child.parts
        if len(self._descriptors) - 1 + len(child_parts) > _MAX_DIRECTORY_DEPTH:
            raise ConfigurationError("runtime directory path is too deep")
        duplicate = self.duplicate()
        descriptors = list(duplicate._descriptors)
        names = list(duplicate._names)
        identities = list(duplicate._identities)
        duplicate._finalizer.detach()
        try:
            for index, component in enumerate(child_parts):
                descriptor = _open_directory_component(
                    descriptors[-1],
                    component,
                )
                descriptors.append(descriptor)
                names.append(component)
                identities.append(
                    _directory_identity(
                        descriptor,
                        private=(
                            self._require_private and index == len(child_parts) - 1
                        ),
                    )
                )
                _validate_public_component(
                    descriptors[-2],
                    component,
                    identities[-1],
                )
            if expected_identity is not None and identities[-1] != expected_identity:
                raise ConfigurationError(
                    "runtime child directory differs from the approved identity"
                )
            pinned = type(self)(
                path=self._path.joinpath(*child_parts),
                descriptors=tuple(descriptors),
                names=tuple(names),
                identities=tuple(identities),
                require_private=self._require_private,
            )
            pinned.validate()
            return pinned
        except BaseException:
            _close_descriptor_values(descriptors)
            raise

    def validate(self) -> None:
        """Fail closed unless every retained descriptor and public edge is stable."""

        with self._lock:
            if not self._finalizer.alive:
                raise ConfigurationError("runtime directory is closed")
            for index, (descriptor, identity) in enumerate(
                zip(self._descriptors, self._identities, strict=True)
            ):
                current = os.fstat(descriptor)
                if not identity.matches(current):
                    raise ConfigurationError("runtime directory identity changed")
                if index == len(self._descriptors) - 1 and self._require_private:
                    _validate_private_directory(current)
                if index:
                    name = self._names[index]
                    if name is None:
                        raise ConfigurationError(
                            "runtime directory descriptor chain is invalid"
                        )
                    _validate_public_component(
                        self._descriptors[index - 1],
                        name,
                        identity,
                    )

    def close(self) -> None:
        """Release all owned descriptors."""

        self._finalizer()

    def __enter__(self) -> Self:
        self.validate()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def pin_directory(
    value: Path | PinnedDirectory,
    *,
    create: bool = False,
) -> PinnedDirectory:
    """Return an independently owned pin for a path or existing pin."""

    if isinstance(value, PinnedDirectory):
        return value.duplicate()
    return PinnedDirectory.open(value, create=create)


class _WindowsPinnedDirectory(PinnedDirectory):
    """Expose a native retained Windows handle chain through the common pin API."""

    def __init__(self, native: Any, *, require_private: bool) -> None:
        self._native = native
        self._require_private = require_private

    @classmethod
    def open_native(
        cls,
        path: Path,
        *,
        expected_identity: DirectoryIdentity | PlatformObjectIdentity | None,
        require_private: bool,
    ) -> _WindowsPinnedDirectory:
        from master_agent.platform_runtime.windows.filesystem import (
            WindowsObjectIdentity,
            WindowsSecureFilesystemBackend,
        )

        backend = get_secure_filesystem_backend()
        if not isinstance(backend, WindowsSecureFilesystemBackend):
            raise ConfigurationError("native Windows secure filesystem is unavailable")
        native_expected: WindowsObjectIdentity | None = None
        if isinstance(expected_identity, DirectoryIdentity):
            raise ConfigurationError(
                "runtime directory identity platform differs from this host"
            )
        if expected_identity is not None:
            native_expected = _windows_native_identity(expected_identity)
        try:
            native = backend.pin_directory(
                path,
                require_private=require_private,
                expected_identity=native_expected,
            )
        except OSError as error:
            raise ConfigurationError(
                "runtime directory could not be opened safely"
            ) from error
        return cls(native, require_private=require_private)

    @property
    def path(self) -> Path:
        return cast(Path, self._native.path)

    @property
    def identity(self) -> DirectoryIdentity:
        raise ConfigurationError("POSIX directory identity is unavailable on Windows")

    @property
    def object_identity(self) -> PlatformObjectIdentity:
        return _platform_identity_from_windows(self._native.identity)

    @property
    def closed(self) -> bool:
        return cast(bool, self._native.closed)

    def fileno(self) -> int:
        raise ConfigurationError(
            "POSIX descriptor-relative directory access is unavailable on Windows"
        )

    def duplicate_fd(self) -> int:
        return self.fileno()

    def duplicate_descriptor_chain(self) -> tuple[int, ...]:
        self.fileno()
        return ()  # pragma: no cover - fileno always raises.

    def duplicate(self) -> PinnedDirectory:
        self.validate()
        return type(self)(
            self._native.duplicate(),
            require_private=self._require_private,
        )

    def pin_child(
        self,
        relative: Path | str,
        *,
        create: bool = False,
        mode: int = 0o700,
        expected_identity: DirectoryIdentity | PlatformObjectIdentity | None = None,
    ) -> PinnedDirectory:
        del mode
        if create:
            raise ConfigurationError("runtime directories must exist before approval")
        if isinstance(expected_identity, DirectoryIdentity):
            raise ConfigurationError(
                "runtime child identity platform differs from this host"
            )
        child = Path(relative)
        if (
            child.is_absolute()
            or not child.parts
            or any(part in {"", ".", ".."} for part in child.parts)
        ):
            raise ConfigurationError(
                "runtime child directory must be a normalized relative path"
            )
        current = cast(_WindowsPinnedDirectory, self.duplicate())
        try:
            for index, part in enumerate(child.parts):
                try:
                    native_child = current._native.pin_child(
                        part,
                        kind="directory",
                        require_private=(
                            self._require_private and index == len(child.parts) - 1
                        ),
                    )
                except OSError as error:
                    raise ConfigurationError(
                        "runtime child directory could not be opened safely"
                    ) from error
                following = type(self)(
                    native_child,
                    require_private=self._require_private,
                )
                current.close()
                current = following
            if (
                expected_identity is not None
                and current.object_identity != expected_identity
            ):
                raise ConfigurationError(
                    "runtime child directory differs from the approved identity"
                )
            return current
        except BaseException:
            current.close()
            raise

    def validate(self) -> None:
        self._native.validate()

    def close(self) -> None:
        self._native.close()

    def list_children(self) -> tuple[str, ...]:
        """Return validated immediate child names without following aliases."""

        return cast(tuple[str, ...], self._native.list_children())

    def read_child_bytes(
        self,
        relative: Path | str,
        *,
        max_bytes: int,
        require_private: bool = True,
    ) -> tuple[Path, bytes, PlatformObjectIdentity]:
        """Pin and bounded-read one exact immediate Windows file child."""

        child = Path(relative)
        if child.is_absolute() or len(child.parts) != 1:
            raise ConfigurationError(
                "runtime file child must be one normalized relative component"
            )
        native_child = self._native.pin_child(
            child.name,
            kind="file",
            require_private=require_private,
        )
        with native_child:
            payload = cast(bytes, native_child.read_bytes(max_bytes))
            return (
                cast(Path, native_child.path),
                payload,
                _platform_identity_from_windows(native_child.identity),
            )


def _platform_identity_from_windows(native: Any) -> PlatformObjectIdentity:
    from master_agent.platform_runtime.windows.filesystem import WindowsObjectKind

    kind = native.kind
    return PlatformObjectIdentity.from_windows(
        kind=(
            FilesystemObjectKind.DIRECTORY
            if kind is WindowsObjectKind.DIRECTORY
            else FilesystemObjectKind.FILE
        ),
        volume_serial=cast(str, native.volume_serial_hex),
        file_id=cast(str, native.file_id_hex),
        owner_sid=cast(str, native.owner_sid),
        dacl_sha256=cast(str, native.dacl_sha256),
        trust_policy_sha256=cast(str, native.trust_policy_sha256),
    )


def _windows_native_identity(identity: PlatformObjectIdentity) -> Any:
    from master_agent.platform_runtime.windows.filesystem import (
        WindowsObjectIdentity,
        WindowsObjectKind,
    )

    if identity.platform != "windows":
        raise ConfigurationError(
            "runtime directory identity platform differs from this host"
        )
    if identity.kind is not FilesystemObjectKind.DIRECTORY:
        raise ConfigurationError("runtime directory identity kind is invalid")
    return WindowsObjectIdentity(
        volume_serial_number=int(cast(str, identity.volume_serial), 16),
        file_id=bytes.fromhex(cast(str, identity.file_id)),
        owner_sid=cast(str, identity.owner_sid),
        dacl_sha256=cast(str, identity.dacl_sha256),
        trust_policy_sha256=cast(str, identity.trust_policy_sha256),
        kind=WindowsObjectKind.DIRECTORY,
    )


def _open_directory_component(
    parent_descriptor: int,
    name: str,
) -> int:
    """Open one preexisting no-follow child directory."""

    try:
        return os.open(name, _directory_open_flags(), dir_fd=parent_descriptor)
    except FileNotFoundError:
        raise ConfigurationError("runtime directory does not exist") from None
    except OSError as error:
        raise ConfigurationError(
            "runtime directory component must be a no-follow directory"
        ) from error


def _directory_identity(descriptor: int, *, private: bool) -> DirectoryIdentity:
    value = os.fstat(descriptor)
    _validate_directory(value)
    if private:
        _validate_private_directory(value)
    return DirectoryIdentity.from_stat(value)


def _validate_directory(value: os.stat_result) -> None:
    if not stat.S_ISDIR(value.st_mode):
        raise ConfigurationError("runtime directory component is not a directory")


def _validate_private_directory(value: os.stat_result) -> None:
    _validate_directory(value)
    if value.st_uid != get_secure_filesystem_backend().real_user_id():
        raise ConfigurationError(
            "runtime directory must be owned by the current account"
        )
    if stat.S_IMODE(value.st_mode) & 0o022:
        raise ConfigurationError(
            "runtime directory must not be group- or world-writable"
        )


def _validate_public_component(
    parent_descriptor: int,
    name: str,
    identity: DirectoryIdentity,
) -> None:
    try:
        public = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise ConfigurationError("runtime directory path was replaced") from error
    if not identity.matches(public):
        raise ConfigurationError("runtime directory path was replaced")


def _directory_open_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if not directory or not no_follow:
        raise ConfigurationError(
            "secure descriptor-backed runtime directories are unavailable"
        )
    return os.O_RDONLY | directory | no_follow | getattr(os, "O_CLOEXEC", 0)


def _duplicate_descriptor(descriptor: int) -> int:
    """Duplicate one descriptor safely above the standard-stream range."""

    try:
        return get_secure_filesystem_backend().duplicate_descriptor(
            descriptor,
            minimum_descriptor=_MINIMUM_INHERITED_DESCRIPTOR,
        )
    except OSError as error:
        raise ConfigurationError("runtime directory could not be duplicated") from error


def _close_descriptors(descriptors: tuple[int, ...], lock: RLock) -> None:
    with lock:
        _close_descriptor_values(descriptors)


def _close_descriptor_values(descriptors: list[int] | tuple[int, ...]) -> None:
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError:
            pass
