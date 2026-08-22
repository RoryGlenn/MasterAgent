"""Focused native-Windows filesystem and locking backend tests."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

from master_agent import directory_safety
from master_agent.errors import ConfigurationError
from master_agent.platform_runtime import (
    FilesystemObjectKind,
    LockMode,
    PlatformCapabilityUnavailable,
    PlatformContract,
)
from master_agent.platform_runtime.windows import (
    BUILTIN_ADMINISTRATORS_SID,
    FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_PINNED,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_UNPINNED,
    LOCAL_SYSTEM_SID,
    TRUSTED_INSTALLER_SID,
    WINDOWS_ANCESTOR_CHILD_CREATE_MASK,
    WINDOWS_DANGEROUS_WRITE_MASK,
    WINDOWS_RUNTIME_BACKEND_ID,
    NativeWindowsFileSnapshot,
    NativeWindowsSecurity,
    NativeWindowsVolume,
    WindowsAccessAllowedAce,
    WindowsCrossProcessLockingBackend,
    WindowsDacl,
    WindowsDaclPolicy,
    WindowsObjectIdentity,
    WindowsObjectKind,
    WindowsPathSecurityError,
    WindowsSecureFilesystemBackend,
    build_protected_windows_sddl,
    build_windows_runtime,
    canonicalize_windows_sid,
    evaluate_windows_dacl,
    parse_windows_ace_header,
    validate_windows_drive_path,
    windows_ace_sid_length,
    windows_file_attributes_are_safe,
    windows_trust_policy_sha256,
)
from master_agent.platform_runtime.windows import native as windows_native
from master_agent.platform_runtime.windows.locking import _NativeWindowsLockApi
from master_agent.platform_runtime.windows.native import NativeWindowsApi

ROOT = Path(__file__).resolve().parents[1]
CURRENT_SID = "S-1-5-21-100-200-300-1001"
OTHER_SID = "S-1-5-21-100-200-300-1002"

_LOCK_CHILD_SCRIPT = """
import os
import sys

from master_agent.platform_runtime import LockMode
from master_agent.platform_runtime.windows import WindowsCrossProcessLockingBackend

path = sys.argv[1]
mode = LockMode(sys.argv[2])
blocking = sys.argv[3] == "blocking"
descriptor = os.open(path, os.O_RDWR)
backend = WindowsCrossProcessLockingBackend()
print("attempting", flush=True)
try:
    try:
        backend.acquire(descriptor, mode=mode, blocking=blocking)
    except BlockingIOError:
        print("blocked", flush=True)
        raise SystemExit(23)
    print("acquired", flush=True)
    backend.release(descriptor)
finally:
    os.close(descriptor)
"""


def _subprocess_environment() -> dict[str, str]:
    environment = dict(os.environ)
    existing = environment.get("PYTHONPATH")
    source = str(ROOT / "src")
    environment["PYTHONPATH"] = (
        source if not existing else source + os.pathsep + existing
    )
    return environment


class _FakeFilesystemApi:
    def __init__(self) -> None:
        self.content = {
            "C:\\Secure\\note.txt": b"trusted payload",
            "C:\\Secure\\nested\\child.txt": b"child payload",
        }
        self.directories = {
            "C:\\": ("Secure",),
            "C:\\Secure": ("note.txt", "nested"),
            "C:\\Secure\\nested": ("child.txt",),
        }
        self.case_sensitive_paths: set[str] = set()
        self.readable_untrusted_paths: set[str] = set()
        self.untrusted_paths: set[str] = set()
        self.writable_untrusted_paths: set[str] = set()
        self.ancestor_child_create_paths: set[str] = set()
        self.attributes: dict[str, int] = {}
        self.security_generation: dict[str, int] = {}
        self.protected_paths: set[str] = set()
        self.created_sddl: list[str] = []
        self.flushed: list[int] = []
        self.open_calls: list[tuple[str, bool, bool]] = []
        self.closed: set[int] = set()
        self.delete_on_close: set[int] = set()
        self._next_handle = 100
        self._paths: dict[int, str] = {}
        self._positions: dict[int, int] = {}

    def current_user_sid(self) -> str:
        return CURRENT_SID

    def volume_information(self, root: str) -> NativeWindowsVolume:
        if root != "C:\\":
            raise AssertionError(root)
        return NativeWindowsVolume(
            drive_type=3,
            serial_number=123,
            filesystem="NTFS",
            maximum_component_length=255,
            filesystem_flags=0x8,
        )

    def open_path(self, path: str, *, directory: bool, readable: bool) -> int:
        known = path in self.directories or path in self.content
        if not known:
            raise FileNotFoundError(path)
        handle = self._next_handle
        self._next_handle += 1
        self._paths[handle] = path
        self._positions[handle] = 0
        self.open_calls.append((path, directory, readable))
        return handle

    def close_handle(self, handle: int) -> None:
        if handle in self.closed:
            raise OSError("double close")
        path = self._paths[handle]
        if handle in self.delete_on_close:
            self.content.pop(path, None)
            parent, name = path.rsplit("\\", 1)
            self.directories[parent] = tuple(
                child for child in self.directories[parent] if child != name
            )
        self.closed.add(handle)

    def duplicate_handle(self, handle: int) -> int:
        path = self._require_handle(handle)
        duplicate = self._next_handle
        self._next_handle += 1
        self._paths[duplicate] = path
        self._positions[duplicate] = self._positions[handle]
        return duplicate

    def file_snapshot(self, handle: int) -> NativeWindowsFileSnapshot:
        path = self._require_handle(handle)
        is_directory = path in self.directories
        payload = self.content.get(path, b"")
        return NativeWindowsFileSnapshot(
            attributes=self.attributes.get(path, 0),
            is_directory=is_directory,
            size=len(payload),
            volume_serial_number=0x123456789ABCDEF0,
            file_id=hashlib.sha256(path.encode("utf-8")).digest()[:16],
        )

    def file_security(self, handle: int) -> NativeWindowsSecurity:
        path = self._require_handle(handle)
        generation = self.security_generation.get(path, 0)
        owner_sid = OTHER_SID if path in self.untrusted_paths else CURRENT_SID
        aces: tuple[WindowsAccessAllowedAce, ...] = ()
        if path in self.untrusted_paths or path in self.writable_untrusted_paths:
            mask = 0x2 if path in self.untrusted_paths else 0x100
            aces = (WindowsAccessAllowedAce(sid=OTHER_SID, access_mask=mask),)
        elif path in self.ancestor_child_create_paths:
            aces = (
                WindowsAccessAllowedAce(
                    sid=OTHER_SID,
                    access_mask=WINDOWS_ANCESTOR_CHILD_CREATE_MASK,
                ),
            )
        elif path in self.readable_untrusted_paths:
            aces = (WindowsAccessAllowedAce(sid=OTHER_SID, access_mask=0x120089),)
        return NativeWindowsSecurity(
            owner_sid=owner_sid,
            dacl=WindowsDacl(
                raw=f"acl:{path}:{generation}".encode(),
                valid=True,
                allow_aces=aces,
            ),
            dacl_protected=path in self.protected_paths,
        )

    def directory_is_case_sensitive(self, handle: int) -> bool:
        return self._require_handle(handle) in self.case_sensitive_paths

    def final_path(self, handle: int) -> str:
        return self._require_handle(handle)

    def directory_names(self, path: str) -> tuple[str, ...]:
        return self.directories[path]

    def rewind_file(self, handle: int) -> None:
        self._require_handle(handle)
        self._positions[handle] = 0

    def read_file(self, handle: int, maximum_bytes: int) -> bytes:
        path = self._require_handle(handle)
        payload = self.content[path]
        position = self._positions[handle]
        value = payload[position : position + maximum_bytes]
        self._positions[handle] += len(value)
        return value

    def create_private_file(
        self,
        parent_handle: int,
        name: str,
        *,
        security_descriptor_sddl: str,
    ) -> int:
        parent = self._require_handle(parent_handle)
        if parent not in self.directories:
            raise NotADirectoryError(parent)
        if any(
            child.casefold() == name.casefold() for child in self.directories[parent]
        ):
            raise FileExistsError(name)
        path = parent.rstrip("\\") + "\\" + name
        self.content[path] = b""
        self.directories[parent] = (*self.directories[parent], name)
        self.protected_paths.add(path)
        self.created_sddl.append(security_descriptor_sddl)
        handle = self._next_handle
        self._next_handle += 1
        self._paths[handle] = path
        self._positions[handle] = 0
        return handle

    def write_file(self, handle: int, payload: bytes) -> int:
        path = self._require_handle(handle)
        position = self._positions[handle]
        current = self.content[path]
        self.content[path] = (
            current[:position] + payload + current[position + len(payload) :]
        )
        self._positions[handle] += len(payload)
        return len(payload)

    def flush_file(self, handle: int) -> None:
        self._require_handle(handle)
        self.flushed.append(handle)

    def set_delete_on_close(self, handle: int, *, enabled: bool) -> None:
        self._require_handle(handle)
        if enabled:
            self.delete_on_close.add(handle)
        else:
            self.delete_on_close.discard(handle)

    def _require_handle(self, handle: int) -> str:
        if handle in self.closed or handle not in self._paths:
            raise OSError("invalid handle")
        return self._paths[handle]


class _FakeLockApi:
    def __init__(self, *, error: int | None = None) -> None:
        self.error = error
        self.acquisitions: list[tuple[int, bool, bool]] = []
        self.releases: list[int] = []

    def acquire(
        self,
        descriptor: int,
        *,
        exclusive: bool,
        blocking: bool,
    ) -> int | None:
        self.acquisitions.append((descriptor, exclusive, blocking))
        return self.error

    def release(self, descriptor: int) -> None:
        self.releases.append(descriptor)


class WindowsPurePolicyTests(unittest.TestCase):
    """Exercise policy helpers without loading a Windows DLL."""

    def test_windows_package_import_is_lazy_on_non_windows(self) -> None:
        script = """
import sys
import master_agent.platform_runtime.windows
assert 'master_agent.platform_runtime.windows.native' not in sys.modules
assert 'msvcrt' not in sys.modules
"""
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_drive_path_validation_is_strict_and_deterministic(self) -> None:
        selected = validate_windows_drive_path("c:/Users/Rory/state.db")
        self.assertEqual(selected.drive, "C")
        self.assertEqual(selected.components, ("Users", "Rory", "state.db"))
        self.assertEqual(selected.canonical, "C:\\Users\\Rory\\state.db")
        self.assertEqual(selected.extended, "\\\\?\\C:\\Users\\Rory\\state.db")
        self.assertEqual(selected.prefixes()[0], "C:\\")
        self.assertEqual(validate_windows_drive_path("D:\\").components, ())

        unsafe = (
            r"\\server\share\state.db",
            r"\\?\C:\state.db",
            r"\\.\C:\state.db",
            r"\??\C:\state.db",
            r"C:relative\state.db",
            r"\rooted\state.db",
            r"C:\safe\..\state.db",
            r"C:\safe\.\state.db",
            r"C:\safe\\state.db",
            r"C:\safe\state.db:secret",
            r"C:\safe\CON.txt",
            r"C:\safe\LPT9",
            r"C:\safe\CLOCK$",
            r"C:\safe\CON .txt",
            "C:\\safe\\name. ",
            "C:\\safe\\name.",
            "C:\\safe\\bad?.txt",
        )
        for value in unsafe:
            with self.subTest(value=value), self.assertRaises(WindowsPathSecurityError):
                validate_windows_drive_path(value)

    def test_sid_canonicalization_and_dacl_evaluation(self) -> None:
        self.assertEqual(canonicalize_windows_sid("S-01-005-018"), LOCAL_SYSTEM_SID)
        for invalid in ("", "S-2-5-18", "S-1-5", " S-1-5-18", "S-1-5--18"):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                canonicalize_windows_sid(invalid)

        trusted_sids = (CURRENT_SID, LOCAL_SYSTEM_SID, BUILTIN_ADMINISTRATORS_SID)
        read_only = WindowsDacl(
            raw=b"read-only",
            valid=True,
            allow_aces=(WindowsAccessAllowedAce(OTHER_SID, 0x120089),),
        )
        writable = WindowsDacl(
            raw=b"writable",
            valid=True,
            allow_aces=(
                WindowsAccessAllowedAce(OTHER_SID, WINDOWS_DANGEROUS_WRITE_MASK),
            ),
        )
        decision = evaluate_windows_dacl(
            owner_sid=CURRENT_SID,
            dacl=writable,
            trusted_sids=trusted_sids,
        )
        self.assertFalse(decision.trusted)
        self.assertEqual(
            decision.reason,
            "Windows DACL grants write-capable access to an untrusted SID",
        )
        inherited_only = WindowsDacl(
            raw=b"inherit-only",
            valid=True,
            allow_aces=(
                WindowsAccessAllowedAce(
                    OTHER_SID,
                    WINDOWS_DANGEROUS_WRITE_MASK,
                    flags=0x08,
                ),
            ),
        )
        self.assertTrue(
            evaluate_windows_dacl(
                owner_sid=CURRENT_SID,
                dacl=inherited_only,
                trusted_sids=trusted_sids,
            ).trusted
        )
        self.assertFalse(
            evaluate_windows_dacl(
                owner_sid=OTHER_SID,
                dacl=writable,
                trusted_sids=trusted_sids,
                require_private=False,
            ).trusted
        )
        self.assertTrue(
            evaluate_windows_dacl(
                owner_sid=CURRENT_SID,
                dacl=read_only,
                trusted_sids=trusted_sids,
                require_private=False,
            ).trusted
        )
        private_read = evaluate_windows_dacl(
            owner_sid=CURRENT_SID,
            dacl=read_only,
            trusted_sids=trusted_sids,
            require_private=True,
        )
        self.assertFalse(private_read.trusted)
        self.assertEqual(
            private_read.reason,
            "Windows private DACL grants access to an untrusted SID",
        )
        ancestor_child_creation = WindowsDacl(
            raw=b"ancestor-child-creation",
            valid=True,
            allow_aces=(
                WindowsAccessAllowedAce(
                    OTHER_SID,
                    WINDOWS_ANCESTOR_CHILD_CREATE_MASK,
                ),
            ),
        )
        self.assertTrue(
            evaluate_windows_dacl(
                owner_sid=CURRENT_SID,
                dacl=ancestor_child_creation,
                trusted_sids=trusted_sids,
                policy=WindowsDaclPolicy.ANCESTOR,
            ).trusted
        )
        self.assertFalse(
            evaluate_windows_dacl(
                owner_sid=CURRENT_SID,
                dacl=ancestor_child_creation,
                trusted_sids=trusted_sids,
                require_private=False,
            ).trusted
        )
        for mask in (0x40, 0x100, 0x40000, 0x80000):
            with self.subTest(ancestor_dangerous_mask=mask):
                self.assertFalse(
                    evaluate_windows_dacl(
                        owner_sid=CURRENT_SID,
                        dacl=WindowsDacl(
                            raw=b"dangerous-ancestor",
                            valid=True,
                            allow_aces=(WindowsAccessAllowedAce(OTHER_SID, mask),),
                        ),
                        trusted_sids=trusted_sids,
                        policy=WindowsDaclPolicy.ANCESTOR,
                    ).trusted
                )
        self.assertFalse(
            evaluate_windows_dacl(
                owner_sid=CURRENT_SID,
                dacl=WindowsDacl(raw=None, valid=False, allow_aces=()),
                trusted_sids=trusted_sids,
            ).trusted
        )
        self.assertFalse(
            evaluate_windows_dacl(
                owner_sid=CURRENT_SID,
                dacl=WindowsDacl(raw=b"invalid", valid=False, allow_aces=()),
                trusted_sids=trusted_sids,
            ).trusted
        )

    def test_reparse_cloud_and_offline_attributes_are_rejected(self) -> None:
        self.assertTrue(windows_file_attributes_are_safe(0))
        for attribute in (
            FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_ATTRIBUTE_OFFLINE,
            FILE_ATTRIBUTE_RECALL_ON_OPEN,
            FILE_ATTRIBUTE_PINNED,
            FILE_ATTRIBUTE_UNPINNED,
            FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        ):
            with self.subTest(attribute=attribute):
                self.assertFalse(windows_file_attributes_are_safe(attribute))

    def test_ace_header_parser_rejects_inexact_allow_forms(self) -> None:
        self.assertEqual(parse_windows_ace_header(b"\x00\x08\x14\x00"), (0, 8, 20))
        self.assertEqual(parse_windows_ace_header(b"\x05\x00\x20\x00"), (5, 0, 32))
        self.assertEqual(parse_windows_ace_header(b"\x01\x00\x0c\x00"), (1, 0, 12))
        for ace_type in (0x04, 0x09, 0x0B):
            with (
                self.subTest(ace_type=ace_type),
                self.assertRaisesRegex(
                    WindowsPathSecurityError,
                    "unsupported access-allowed ACE",
                ),
            ):
                parse_windows_ace_header(bytes((ace_type, 0, 12, 0)))
        with self.assertRaisesRegex(WindowsPathSecurityError, "unknown ACE type"):
            parse_windows_ace_header(b"\xff\x00\x08\x00")
        with self.assertRaisesRegex(WindowsPathSecurityError, "invalid ACE header"):
            parse_windows_ace_header(b"\x00\x00\x08")

        sid = b"\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00"
        self.assertEqual(windows_ace_sid_length(b"\x00" * 8 + sid, sid_offset=8), 12)
        with self.assertRaisesRegex(WindowsPathSecurityError, "truncated SID"):
            windows_ace_sid_length(b"\x00" * 8 + b"\x01", sid_offset=8)
        with self.assertRaisesRegex(WindowsPathSecurityError, "truncated SID"):
            windows_ace_sid_length(
                b"\x00" * 8 + b"\x01\x0f" + b"\x00" * 10,
                sid_offset=8,
            )
        native_sid_calls: list[object] = []
        truncated_ace = ctypes.create_string_buffer(
            b"\x00\x00\x09\x00" + b"\x01\x00\x00\x00" + b"\x01"
        )
        api = object.__new__(NativeWindowsApi)
        api._advapi32 = SimpleNamespace(
            IsValidSid=lambda value: native_sid_calls.append(value) or 1
        )
        with self.assertRaisesRegex(WindowsPathSecurityError, "truncated SID"):
            api._parse_allow_ace(ctypes.addressof(truncated_ace))
        self.assertEqual(native_sid_calls, [])

        unsupported_object_ace = ctypes.create_string_buffer(
            b"\x05\x00\x0c\x00" + b"\x00" * 4 + b"\x04\x00\x00\x00"
        )
        with self.assertRaisesRegex(
            WindowsPathSecurityError,
            "unsupported object ACE flags",
        ):
            api._parse_allow_ace(ctypes.addressof(unsupported_object_ace))

    def test_writefile_abi_uses_exact_five_argument_layout(self) -> None:
        calls: list[tuple[int, bytes, int, object | None]] = []

        def write_file(
            handle: ctypes.c_void_p,
            buffer: object,
            size: int,
            observed: object,
            overlapped: object | None,
        ) -> int:
            calls.append(
                (
                    int(handle.value or 0),
                    ctypes.string_at(buffer, size),
                    size,
                    overlapped,
                )
            )
            ctypes.cast(observed, ctypes.POINTER(ctypes.c_uint32)).contents.value = size
            return 1

        api = object.__new__(NativeWindowsApi)
        api._kernel32 = SimpleNamespace(WriteFile=write_file)
        self.assertEqual(api.write_file(0x1234, b"payload"), 7)
        self.assertEqual(calls, [(0x1234, b"payload", 7, None)])

    def test_post_create_validation_failure_deletes_exact_native_entry(self) -> None:
        def exercise(failure: str) -> None:
            events: list[str] = []
            state = {"entry": False, "delete_pending": False}

            def convert_descriptor(
                _sddl: object,
                _revision: int,
                descriptor: object,
                descriptor_size: object,
            ) -> int:
                ctypes.cast(
                    descriptor,
                    ctypes.POINTER(ctypes.c_void_p),
                ).contents.value = 0x9000
                ctypes.cast(
                    descriptor_size,
                    ctypes.POINTER(ctypes.c_uint32),
                ).contents.value = 64
                return 1

            def nt_create(created: object, *_args: object) -> int:
                ctypes.cast(
                    created,
                    ctypes.POINTER(ctypes.c_void_p),
                ).contents.value = 0x1234
                state["entry"] = True
                events.append("create")
                return 0

            def get_file_type(_handle: object) -> int:
                events.append("file-type")
                return 0 if failure == "file-type" else 1

            def set_handle_information(*_args: object) -> int:
                events.append("set-inheritability")
                return 0 if failure == "inheritability" else 1

            def set_file_information(*_args: object) -> int:
                events.append("delete-disposition")
                state["delete_pending"] = True
                return 1

            def close_handle(_handle: object) -> int:
                events.append("close")
                if state["delete_pending"]:
                    state["entry"] = False
                return 1

            api = object.__new__(NativeWindowsApi)
            api._advapi32 = SimpleNamespace(
                ConvertStringSecurityDescriptorToSecurityDescriptorW=(
                    convert_descriptor
                )
            )
            api._ntdll = SimpleNamespace(
                NtCreateFile=nt_create,
                RtlNtStatusToDosError=lambda _status: 5,
            )
            api._kernel32 = SimpleNamespace(
                CloseHandle=close_handle,
                GetFileType=get_file_type,
                LocalFree=lambda _value: None,
                SetFileInformationByHandle=set_file_information,
                SetHandleInformation=set_handle_information,
            )
            with (
                patch.object(windows_native, "_last_error", return_value=5),
                self.assertRaises((OSError, WindowsPathSecurityError)),
            ):
                api.create_private_file(
                    0x99,
                    "new.bin",
                    security_descriptor_sddl=f"O:{CURRENT_SID}D:P",
                )
            self.assertLess(
                events.index("delete-disposition"),
                events.index("close"),
            )
            self.assertFalse(state["entry"])

        for failure in ("file-type", "inheritability"):
            with self.subTest(failure=failure):
                exercise(failure)

    def test_creation_descriptor_is_freed_when_name_setup_fails(self) -> None:
        frees: list[int] = []

        def convert_descriptor(
            _sddl: object,
            _revision: int,
            descriptor: object,
            descriptor_size: object,
        ) -> int:
            ctypes.cast(
                descriptor,
                ctypes.POINTER(ctypes.c_void_p),
            ).contents.value = 0x9000
            ctypes.cast(
                descriptor_size,
                ctypes.POINTER(ctypes.c_uint32),
            ).contents.value = 64
            return 1

        api = object.__new__(NativeWindowsApi)
        api._advapi32 = SimpleNamespace(
            ConvertStringSecurityDescriptorToSecurityDescriptorW=convert_descriptor
        )
        api._kernel32 = SimpleNamespace(
            LocalFree=lambda value: frees.append(int(value.value or 0))
        )
        with self.assertRaises((UnicodeEncodeError, ValueError)):
            api.create_private_file(
                0x99,
                "\ud800",
                security_descriptor_sddl=f"O:{CURRENT_SID}D:P",
            )
        self.assertEqual(frees, [0x9000])

    def test_object_identity_has_lossless_conversion_values(self) -> None:
        identity = WindowsObjectIdentity(
            volume_serial_number=0x123456789ABCDEF0,
            file_id=bytes.fromhex("00112233445566778899aabbccddeeff"),
            owner_sid=CURRENT_SID,
            dacl_sha256="a" * 64,
            trust_policy_sha256="b" * 64,
            kind=WindowsObjectKind.FILE,
        )
        self.assertEqual(identity.volume_serial_hex, "123456789abcdef0")
        self.assertEqual(identity.file_id_hex, "00112233445566778899aabbccddeeff")
        self.assertEqual(identity.to_dict()["kind"], "file")

    def test_trust_policy_digest_binds_mode_and_exact_sid_set(self) -> None:
        trusted = (CURRENT_SID, LOCAL_SYSTEM_SID, BUILTIN_ADMINISTRATORS_SID)
        by_mode = {
            windows_trust_policy_sha256(trusted, policy=policy)
            for policy in WindowsDaclPolicy
        }
        self.assertEqual(len(by_mode), len(WindowsDaclPolicy))
        extended = windows_trust_policy_sha256(
            (*trusted, TRUSTED_INSTALLER_SID),
            policy=WindowsDaclPolicy.ANCESTOR,
        )
        self.assertNotIn(extended, by_mode)

    def test_protected_creation_sddl_is_explicit_and_policy_derived(self) -> None:
        value = build_protected_windows_sddl(
            owner_sid=CURRENT_SID,
            trusted_sids=(
                BUILTIN_ADMINISTRATORS_SID,
                CURRENT_SID,
                LOCAL_SYSTEM_SID,
                TRUSTED_INSTALLER_SID,
            ),
        )
        self.assertEqual(
            value,
            f"O:{CURRENT_SID}D:P"
            f"(A;;FA;;;{CURRENT_SID})"
            f"(A;;FA;;;{LOCAL_SYSTEM_SID})"
            f"(A;;FA;;;{BUILTIN_ADMINISTRATORS_SID})"
            f"(A;;FA;;;{TRUSTED_INSTALLER_SID})",
        )
        with self.assertRaisesRegex(ValueError, "part of the trust policy"):
            build_protected_windows_sddl(
                owner_sid=CURRENT_SID,
                trusted_sids=(LOCAL_SYSTEM_SID,),
            )

    def test_partial_runtime_status_is_complete_without_loading_native_state(
        self,
    ) -> None:
        with (
            patch(
                "master_agent.platform_runtime.windows.runtime.sys.platform",
                "win32",
            ),
            patch(
                "master_agent.platform_runtime.windows.runtime."
                "probe_windows_filesystem_backend"
            ) as filesystem_probe,
            patch(
                "master_agent.platform_runtime.windows.runtime."
                "probe_windows_locking_backend"
            ) as locking_probe,
        ):
            runtime = build_windows_runtime()
        filesystem_probe.assert_called_once_with()
        locking_probe.assert_called_once_with()
        self.assertEqual(runtime.status.backend, WINDOWS_RUNTIME_BACKEND_ID)
        self.assertTrue(runtime.supports(PlatformContract.SECURE_FILESYSTEM))
        self.assertTrue(runtime.supports(PlatformContract.CROSS_PROCESS_LOCKING))
        for contract in (
            PlatformContract.ATOMIC_PUBLICATION_RECOVERY,
            PlatformContract.PROCESS_SUPERVISION,
            PlatformContract.TRUSTED_GIT,
            PlatformContract.CAPSULE_ISOLATION,
        ):
            status = runtime.status.contract_status(contract)
            self.assertFalse(status.available)
            self.assertEqual(status.backend, WINDOWS_RUNTIME_BACKEND_ID)
            self.assertEqual(
                status.reason,
                f"native windows {contract} backend is not implemented",
            )


class WindowsPinnedPathTests(unittest.TestCase):
    """Exercise handle-chain behavior through a deterministic native adapter."""

    def test_pin_rejects_unsupported_volume_before_opening_handles(self) -> None:
        cases = (
            (
                "remote drive",
                NativeWindowsVolume(
                    drive_type=4,
                    serial_number=123,
                    filesystem="NTFS",
                    maximum_component_length=255,
                    filesystem_flags=0x8,
                ),
                "volume is not fixed",
            ),
            (
                "unsupported filesystem",
                NativeWindowsVolume(
                    drive_type=3,
                    serial_number=123,
                    filesystem="FAT32",
                    maximum_component_length=255,
                    filesystem_flags=0x8,
                ),
                "filesystem is not NTFS or ReFS",
            ),
            (
                "filesystem without persistent ACLs",
                NativeWindowsVolume(
                    drive_type=3,
                    serial_number=123,
                    filesystem="NTFS",
                    maximum_component_length=255,
                    filesystem_flags=0,
                ),
                "filesystem does not preserve ACLs",
            ),
        )
        for label, volume, message in cases:
            with self.subTest(label=label):
                api = _FakeFilesystemApi()
                backend = WindowsSecureFilesystemBackend(_api=api)
                with (
                    patch.object(api, "volume_information", return_value=volume),
                    self.assertRaisesRegex(WindowsPathSecurityError, message),
                ):
                    backend.pin_file(r"C:\Secure\note.txt")
                self.assertEqual(api.open_calls, [])

    def test_pin_read_duplicate_child_and_close_complete_handle_chains(self) -> None:
        api = _FakeFilesystemApi()
        backend = WindowsSecureFilesystemBackend(_api=api)
        with backend.pin_file(r"C:\Secure\note.txt") as pinned:
            self.assertEqual(pinned.read_bytes(1024), b"trusted payload")
            self.assertEqual(pinned.identity.kind, WindowsObjectKind.FILE)
            self.assertEqual(len(pinned.identity.file_id), 16)
            pinned.validate()
            with pinned.duplicate() as duplicate:
                self.assertEqual(duplicate.identity, pinned.identity)
                self.assertEqual(duplicate.read_bytes(1024), b"trusted payload")
            expected = pinned.identity
        self.assertTrue(pinned.closed)

        with backend.pin_file(
            r"C:\Secure\note.txt",
            expected_identity=expected,
        ) as rebound:
            self.assertEqual(rebound.identity, expected)

        with backend.pin_directory(r"C:\Secure") as directory:
            self.assertEqual(directory.list_children(), ("nested", "note.txt"))
            with directory.pin_child(
                "note.txt",
                kind=WindowsObjectKind.FILE,
                require_private=True,
            ) as child:
                self.assertEqual(child.read_bytes(1024), b"trusted payload")
        self.assertEqual(
            api.open_calls[:3],
            [
                ("C:\\", True, False),
                ("C:\\Secure", True, False),
                ("C:\\Secure\\note.txt", False, True),
            ],
        )

    def test_read_restricted_file_is_bounded_and_returns_identity(self) -> None:
        api = _FakeFilesystemApi()
        backend = WindowsSecureFilesystemBackend(_api=api)
        path, payload, identity = backend.read_restricted_file(
            r"C:\Secure\note.txt",
            1024,
        )
        self.assertEqual(str(path), r"C:\Secure\note.txt")
        self.assertEqual(payload, b"trusted payload")
        self.assertEqual(identity.kind, WindowsObjectKind.FILE)
        with self.assertRaisesRegex(
            WindowsPathSecurityError,
            "exceeds the bounded read limit",
        ):
            backend.read_restricted_file(r"C:\Secure\note.txt", 1)

    def test_pin_rejects_security_drift_case_sensitive_dirs_and_attributes(
        self,
    ) -> None:
        api = _FakeFilesystemApi()
        backend = WindowsSecureFilesystemBackend(_api=api)
        pinned = backend.pin_file(r"C:\Secure\note.txt")
        api.security_generation[r"C:\Secure"] = 1
        with self.assertRaisesRegex(
            WindowsPathSecurityError,
            "identity or security changed",
        ):
            pinned.validate()
        pinned.close()

        case_api = _FakeFilesystemApi()
        case_api.case_sensitive_paths.add(r"C:\Secure")
        with self.assertRaisesRegex(
            WindowsPathSecurityError,
            "case-sensitive Windows directories",
        ):
            WindowsSecureFilesystemBackend(_api=case_api).pin_file(
                r"C:\Secure\note.txt"
            )

        attribute_api = _FakeFilesystemApi()
        attribute_api.attributes[r"C:\Secure\note.txt"] = FILE_ATTRIBUTE_OFFLINE
        with self.assertRaisesRegex(
            WindowsPathSecurityError,
            "reparse, cloud, or offline",
        ):
            WindowsSecureFilesystemBackend(_api=attribute_api).pin_file(
                r"C:\Secure\note.txt"
            )

        collision_api = _FakeFilesystemApi()
        collision_api.directories[r"C:\Secure"] = (
            "nested",
            "note.txt",
            "NOTE.TXT",
        )
        with self.assertRaisesRegex(
            WindowsPathSecurityError,
            "case-insensitive name collision",
        ):
            WindowsSecureFilesystemBackend(_api=collision_api).pin_file(
                r"C:\Secure\note.txt"
            )

    def test_ancestor_child_creation_is_safe_but_target_or_metadata_write_is_not(
        self,
    ) -> None:
        api = _FakeFilesystemApi()
        api.ancestor_child_create_paths.update(("C:\\", r"C:\Secure"))
        with WindowsSecureFilesystemBackend(_api=api).pin_file(
            r"C:\Secure\note.txt",
            require_private=True,
        ) as pinned:
            self.assertEqual(pinned.read_bytes(1024), b"trusted payload")

        api = _FakeFilesystemApi()
        api.ancestor_child_create_paths.add(r"C:\Secure\note.txt")
        with self.assertRaisesRegex(
            WindowsPathSecurityError,
            "write-capable access to an untrusted SID",
        ):
            WindowsSecureFilesystemBackend(_api=api).pin_file(
                r"C:\Secure\note.txt",
                require_private=False,
            )

        api = _FakeFilesystemApi()
        api.writable_untrusted_paths.add(r"C:\Secure")
        with self.assertRaisesRegex(
            WindowsPathSecurityError,
            "write-capable access to an untrusted SID",
        ):
            WindowsSecureFilesystemBackend(_api=api).pin_file(
                r"C:\Secure\note.txt",
                require_private=True,
            )

    def test_private_dacl_is_default_and_additional_sid_is_explicit(self) -> None:
        api = _FakeFilesystemApi()
        api.untrusted_paths.add(r"C:\Secure\note.txt")
        backend = WindowsSecureFilesystemBackend(_api=api)
        with self.assertRaisesRegex(
            WindowsPathSecurityError,
            "owner SID is not trusted",
        ):
            backend.pin_file(r"C:\Secure\note.txt")

        api = _FakeFilesystemApi()
        api.untrusted_paths.add(r"C:\Secure\note.txt")
        backend = WindowsSecureFilesystemBackend(
            additional_trusted_sids=(OTHER_SID,),
            _api=api,
        )
        with backend.pin_file(r"C:\Secure\note.txt") as pinned:
            self.assertEqual(pinned.identity.owner_sid, OTHER_SID)

        api = _FakeFilesystemApi()
        api.readable_untrusted_paths.add(r"C:\Secure\note.txt")
        with WindowsSecureFilesystemBackend(_api=api).pin_file(
            r"C:\Secure\note.txt",
            require_private=False,
        ) as identity_only:
            self.assertEqual(identity_only.identity.owner_sid, CURRENT_SID)

        api = _FakeFilesystemApi()
        api.untrusted_paths.add(r"C:\Secure\note.txt")
        with self.assertRaisesRegex(
            WindowsPathSecurityError,
            "owner SID is not trusted",
        ):
            WindowsSecureFilesystemBackend(_api=api).pin_file(
                r"C:\Secure\note.txt",
                require_private=False,
            )

    def test_expected_identity_mismatch_fails_closed(self) -> None:
        api = _FakeFilesystemApi()
        backend = WindowsSecureFilesystemBackend(_api=api)
        with backend.pin_file(r"C:\Secure\note.txt") as pinned:
            wrong = replace(pinned.identity, file_id=b"x" * 16)
        with self.assertRaisesRegex(
            WindowsPathSecurityError,
            "expected identity",
        ):
            backend.pin_file(r"C:\Secure\note.txt", expected_identity=wrong)

    def test_revalidation_recomputes_the_bound_trust_policy_digest(self) -> None:
        api = _FakeFilesystemApi()
        backend = WindowsSecureFilesystemBackend(_api=api)
        pinned = backend.pin_file(r"C:\Secure\note.txt")
        pinned._identities = (
            *pinned._identities[:-1],
            replace(pinned.identity, trust_policy_sha256="0" * 64),
        )
        try:
            with self.assertRaisesRegex(
                WindowsPathSecurityError,
                "identity or security changed",
            ):
                pinned.validate()
        finally:
            pinned.close()

    def test_exclusive_private_creation_writes_flushes_and_publishes(self) -> None:
        api = _FakeFilesystemApi()
        backend = WindowsSecureFilesystemBackend(_api=api)
        with backend.pin_directory(r"C:\Secure") as directory:
            with directory.create_private_file("created.bin", max_bytes=64) as created:
                self.assertEqual(created.identity.kind, WindowsObjectKind.FILE)
                self.assertTrue(
                    created.identity.dacl_sha256
                    != hashlib.sha256(b"acl:C:\\Secure\\created.bin:0").hexdigest()
                )
                created.write_bytes(b"new payload")
                self.assertEqual(created.read_bytes(64), b"new payload")
                identity = created.publish()
                self.assertTrue(created.published)
                self.assertTrue(created.closed)
            self.assertIn("D:P", api.created_sddl[-1])
            self.assertTrue(api.flushed)
            self.assertEqual(api.content[r"C:\Secure\created.bin"], b"new payload")
            with directory.pin_child(
                "created.bin",
                kind=WindowsObjectKind.FILE,
                require_private=True,
            ) as reopened:
                self.assertEqual(reopened.identity, identity)
                self.assertEqual(reopened.read_bytes(64), b"new payload")

            with self.assertRaises(FileExistsError):
                directory.create_private_file("created.bin", max_bytes=64)

    def test_created_file_size_bound_and_unpublished_cleanup_are_exact(self) -> None:
        api = _FakeFilesystemApi()
        backend = WindowsSecureFilesystemBackend(_api=api)
        with backend.pin_directory(r"C:\Secure") as directory:
            with (
                self.assertRaisesRegex(
                    WindowsPathSecurityError,
                    "bounded write limit",
                ),
                directory.create_private_file("too-large.bin", max_bytes=2) as created,
            ):
                created.write_bytes(b"three")
            self.assertNotIn(r"C:\Secure\too-large.bin", api.content)

            created = directory.create_private_file("cleanup.bin", max_bytes=16)
            created.write_bytes(b"temporary")
            identity = created.identity
            created.cleanup()
            self.assertTrue(created.closed)
            self.assertNotIn(r"C:\Secure\cleanup.bin", api.content)
            self.assertEqual(identity.kind, WindowsObjectKind.FILE)

    def test_created_file_security_drift_prevents_identity_cleanup(self) -> None:
        api = _FakeFilesystemApi()
        backend = WindowsSecureFilesystemBackend(_api=api)
        with backend.pin_directory(r"C:\Secure") as directory:
            created = directory.create_private_file("drift.bin", max_bytes=16)
            created.write_bytes(b"temporary")
            api.security_generation[r"C:\Secure\drift.bin"] = 1
            with self.assertRaisesRegex(
                WindowsPathSecurityError,
                "identity or security changed",
            ):
                created.cleanup()
            self.assertTrue(created.closed)
            self.assertIn(r"C:\Secure\drift.bin", api.content)


class WindowsCommonDirectoryAdapterTests(unittest.TestCase):
    """Exercise the platform-neutral pinned-directory facade with fake Win32."""

    def test_common_adapter_identity_read_nested_duplicate_and_close(self) -> None:
        api = _FakeFilesystemApi()
        backend = WindowsSecureFilesystemBackend(_api=api)
        with patch.object(
            directory_safety,
            "get_secure_filesystem_backend",
            return_value=backend,
        ):
            pinned = directory_safety._WindowsPinnedDirectory.open_native(
                Path(r"C:\Secure"),
                expected_identity=None,
                require_private=True,
            )
        try:
            identity = pinned.object_identity
            self.assertEqual(identity.platform, "windows")
            self.assertIs(identity.kind, FilesystemObjectKind.DIRECTORY)
            with self.assertRaisesRegex(
                ConfigurationError,
                "POSIX descriptor-relative",
            ):
                pinned.fileno()

            child_path, payload, child_identity = pinned.read_child_bytes(
                "note.txt",
                max_bytes=1024,
                require_private=True,
            )
            self.assertEqual(str(child_path), r"C:\Secure\note.txt")
            self.assertEqual(payload, b"trusted payload")
            self.assertIs(child_identity.kind, FilesystemObjectKind.FILE)

            with pinned.pin_child("nested") as nested:
                self.assertEqual(str(nested.path), r"C:\Secure\nested")
                self.assertIs(
                    nested.object_identity.kind,
                    FilesystemObjectKind.DIRECTORY,
                )

            duplicate = pinned.duplicate()
            pinned.close()
            self.assertTrue(pinned.closed)
            duplicate.validate()
            self.assertFalse(duplicate.closed)
            duplicate.close()
            self.assertTrue(duplicate.closed)
        finally:
            pinned.close()


class WindowsLockingTests(unittest.TestCase):
    """Keep LockFileEx mode and contention behavior deterministic."""

    def test_modes_and_release_are_forwarded_exactly(self) -> None:
        api = _FakeLockApi()
        backend = WindowsCrossProcessLockingBackend(_api=api)
        backend.acquire(7, mode=LockMode.SHARED)
        backend.acquire(8, mode=LockMode.EXCLUSIVE, blocking=False)
        backend.release(8)
        self.assertEqual(api.acquisitions, [(7, False, True), (8, True, False)])
        self.assertEqual(api.releases, [8])

    def test_nonblocking_contention_has_stable_blocking_io_error(self) -> None:
        backend = WindowsCrossProcessLockingBackend(_api=_FakeLockApi(error=33))
        with self.assertRaises(BlockingIOError) as raised:
            backend.acquire(7, mode=LockMode.EXCLUSIVE, blocking=False)
        self.assertEqual(raised.exception.errno, errno.EWOULDBLOCK)
        self.assertEqual(
            raised.exception.strerror,
            "cross-process lock is already held",
        )
        with self.assertRaises(OSError) as non_contention:
            WindowsCrossProcessLockingBackend(_api=_FakeLockApi(error=167)).acquire(
                7, mode=LockMode.EXCLUSIVE, blocking=False
            )
        self.assertNotIsInstance(non_contention.exception, BlockingIOError)
        self.assertEqual(non_contention.exception.errno, 167)

    def test_native_lock_api_rejects_asynchronous_descriptor_mode(self) -> None:
        lock_calls: list[object] = []

        def query_mode(
            _handle: object,
            _status: object,
            mode: object,
            _size: int,
            _information_class: int,
        ) -> int:
            ctypes.cast(mode, ctypes.POINTER(ctypes.c_uint32)).contents.value = 0
            return 0

        api = object.__new__(_NativeWindowsLockApi)
        api._msvcrt = SimpleNamespace(get_osfhandle=lambda _descriptor: 0x1234)
        api._ntdll = SimpleNamespace(
            NtQueryInformationFile=query_mode,
            RtlNtStatusToDosError=lambda _status: 5,
        )
        api._kernel32 = SimpleNamespace(
            LockFileEx=lambda *_args: lock_calls.append(_args) or 1
        )
        with self.assertRaisesRegex(OSError, "synchronous Windows CRT descriptor"):
            api.acquire(7, exclusive=True, blocking=False)
        self.assertEqual(lock_calls, [])

    def test_invalid_lock_inputs_fail_before_native_selection(self) -> None:
        backend = WindowsCrossProcessLockingBackend(_api=_FakeLockApi())
        with self.assertRaises(TypeError):
            backend.acquire(True, mode=LockMode.SHARED)
        with self.assertRaises(ValueError):
            backend.acquire(1, mode=cast(LockMode, "invalid"))
        with self.assertRaises(TypeError):
            backend.acquire(1, mode=LockMode.SHARED, blocking=cast(bool, 1))

    @unittest.skipIf(sys.platform == "win32", "non-Windows guard only")
    def test_native_operations_fail_lazily_off_windows(self) -> None:
        with self.assertRaises(PlatformCapabilityUnavailable):
            WindowsSecureFilesystemBackend().current_user_sid()
        with self.assertRaises(PlatformCapabilityUnavailable):
            WindowsCrossProcessLockingBackend().acquire(1, mode=LockMode.SHARED)


@unittest.skipUnless(sys.platform == "win32", "requires native Windows APIs")
class WindowsNativeStandardUserIntegrationTests(unittest.TestCase):
    """Prove inherited ACL and reparse behavior under a limited Windows token."""

    def test_native_runner_is_windows_11_workstation(self) -> None:
        version = sys.getwindowsversion()
        self.assertEqual(
            version.product_type,
            1,
            "Windows native acceptance requires a workstation operating system",
        )
        self.assertGreaterEqual(
            version.build,
            22_000,
            "Windows native acceptance requires Windows 11 or later",
        )

    def test_native_runner_token_is_not_an_administrator(self) -> None:
        self.assertFalse(
            NativeWindowsApi().current_token_is_administrator(),
            "Windows standard-user acceptance must not run as Administrators",
        )

    def test_native_inherited_dacl_admits_then_rejects_live_broadening(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            inherited = root / "inherited"
            inherited.mkdir()
            target = inherited / "payload.bin"
            target.write_bytes(b"inherited payload")
            backend = WindowsSecureFilesystemBackend()
            pinned = backend.pin_file(target, require_private=False)
            try:
                self.assertEqual(pinned.read_bytes(1024), b"inherited payload")
                with pinned.duplicate_target_handle() as target_handle:
                    security = NativeWindowsApi().file_security(target_handle.value)
                self.assertFalse(security.dacl_protected)
                grant = subprocess.run(
                    ["icacls.exe", str(target), "/grant", "*S-1-1-0:(W)"],
                    text=True,
                    capture_output=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(grant.returncode, 0, grant.stderr or grant.stdout)
                with self.assertRaisesRegex(
                    WindowsPathSecurityError,
                    "write-capable access to an untrusted SID",
                ):
                    pinned.validate()
            finally:
                pinned.close()
            with self.assertRaisesRegex(
                WindowsPathSecurityError,
                "write-capable access to an untrusted SID",
            ):
                backend.pin_file(target, require_private=False)

    def test_native_nonprivileged_junction_alias_is_rejected(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            target = root / "junction-target"
            alias = root / "junction-alias"
            target.mkdir()
            created = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(target)],
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(created.returncode, 0, created.stderr or created.stdout)
            try:
                with self.assertRaises((OSError, WindowsPathSecurityError)):
                    WindowsSecureFilesystemBackend().pin_directory(
                        alias,
                        require_private=False,
                    )
            finally:
                os.rmdir(alias)


@unittest.skipUnless(sys.platform == "win32", "requires native Windows APIs")
class WindowsNativeIntegrationTests(unittest.TestCase):
    """Smoke the real Windows 11 handle and LockFileEx paths in hosted CI."""

    @staticmethod
    def _run_lock_child(
        path: Path,
        *,
        mode: LockMode,
        blocking: bool,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-u",
                "-c",
                _LOCK_CHILD_SCRIPT,
                str(path),
                mode.value,
                "blocking" if blocking else "nonblocking",
            ],
            cwd=ROOT,
            env=_subprocess_environment(),
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

    def test_native_inherited_temp_file_pin_identity_read_and_duplicate(self) -> None:
        with TemporaryDirectory() as raw:
            path = Path(raw).resolve() / "native-pin.txt"
            path.write_bytes(b"native Windows payload")
            backend = WindowsSecureFilesystemBackend()
            with backend.pin_file(path, require_private=False) as pinned:
                self.assertEqual(pinned.read_bytes(1024), b"native Windows payload")
                self.assertEqual(pinned.identity.kind, WindowsObjectKind.FILE)
                self.assertEqual(len(pinned.identity.file_id), 16)
                self.assertTrue(pinned.identity.owner_sid.startswith("S-1-"))
                with pinned.duplicate_target_handle() as target_handle:
                    inherited_security = NativeWindowsApi().file_security(
                        target_handle.value
                    )
                self.assertFalse(inherited_security.dacl_protected)
                with self.assertRaises(OSError):
                    path.unlink()
                with pinned.duplicate() as duplicate:
                    duplicate.validate()
                    self.assertEqual(duplicate.identity, pinned.identity)
            path.unlink()
            self.assertFalse(path.exists())

    def test_native_relative_private_create_publish_and_exact_cleanup(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            backend = WindowsSecureFilesystemBackend()
            with backend.pin_directory(root, require_private=True) as directory:
                identity = directory.publish_private_file(
                    "published.bin",
                    b"published payload",
                    max_bytes=1024,
                )
                self.assertEqual(identity.kind, WindowsObjectKind.FILE)
                self.assertEqual(
                    (root / "published.bin").read_bytes(),
                    b"published payload",
                )
                with backend.pin_file(
                    root / "published.bin",
                    require_private=True,
                    expected_identity=identity,
                ) as reopened:
                    reopened.validate()
                    self.assertEqual(reopened.read_bytes(1024), b"published payload")
                with self.assertRaises(FileExistsError):
                    directory.create_private_file("published.bin", max_bytes=1024)
                with directory.create_private_file(
                    "cleanup.bin",
                    max_bytes=1024,
                ) as created:
                    created.write_bytes(b"temporary")
                self.assertFalse((root / "cleanup.bin").exists())

    def test_native_retains_ancestors_against_namespace_replacement(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            ancestor = root / "retained-ancestor"
            ancestor.mkdir()
            target = ancestor / "payload.bin"
            target.write_bytes(b"retained")
            moved = root / "moved-ancestor"
            backend = WindowsSecureFilesystemBackend()
            with backend.pin_file(target, require_private=False) as pinned:
                pinned.validate()
                with self.assertRaises(OSError):
                    ancestor.rename(moved)
            ancestor.rename(moved)
            self.assertEqual((moved / "payload.bin").read_bytes(), b"retained")

    def test_native_rejects_case_alias_and_accepts_unicode(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            canonical = root / "CanonicalName"
            canonical.mkdir()
            target = canonical / "Unicode-Δ-文-🙂.txt"
            target.write_bytes(b"trusted Unicode payload")
            backend = WindowsSecureFilesystemBackend()
            with backend.pin_file(target, require_private=False) as pinned:
                self.assertEqual(
                    pinned.read_bytes(1024),
                    b"trusted Unicode payload",
                )
            alias = root / "canonicalname" / target.name
            self.assertTrue(alias.exists())
            with self.assertRaisesRegex(
                WindowsPathSecurityError,
                "component casing is not canonical",
            ):
                backend.pin_file(alias, require_private=False)

    def test_native_rejects_reparse_alias_when_symlinks_are_available(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            target = root / "target.bin"
            alias = root / "alias.bin"
            target.write_bytes(b"target")
            try:
                alias.symlink_to(target)
            except OSError as exc:
                if getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Windows symlink privilege is unavailable")
                raise
            with self.assertRaises((OSError, WindowsPathSecurityError)):
                WindowsSecureFilesystemBackend().pin_file(
                    alias,
                    require_private=False,
                )

    def test_native_extended_length_path_exceeds_legacy_limit(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            current = root
            created_directories: list[Path] = []
            target: Path | None = None
            try:
                for index in range(4):
                    component = f"{index:02d}-" + "long-path-component-" * 3
                    current /= component
                    os.mkdir(validate_windows_drive_path(current).extended)
                    created_directories.append(current)
                target = current / "payload-文.bin"
                self.assertGreater(len(str(target)), 260)
                descriptor = os.open(
                    validate_windows_drive_path(target).extended,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                try:
                    self.assertEqual(os.write(descriptor, b"long path"), 9)
                finally:
                    os.close(descriptor)
                with WindowsSecureFilesystemBackend().pin_file(
                    target,
                    require_private=False,
                ) as pinned:
                    self.assertEqual(pinned.read_bytes(64), b"long path")
            finally:
                if target is not None:
                    try:
                        os.unlink(validate_windows_drive_path(target).extended)
                    except FileNotFoundError:
                        pass
                for directory in reversed(created_directories):
                    try:
                        os.rmdir(validate_windows_drive_path(directory).extended)
                    except FileNotFoundError:
                        pass

    def test_native_lockfileex_shared_exclusive_and_nonblocking(self) -> None:
        with TemporaryDirectory() as raw:
            path = Path(raw) / "native-lock.bin"
            path.write_bytes(b"lock")
            first = os.open(path, os.O_RDWR)
            second = os.open(path, os.O_RDWR)
            backend = WindowsCrossProcessLockingBackend()
            try:
                backend.acquire(first, mode=LockMode.EXCLUSIVE)
                with self.assertRaises(BlockingIOError):
                    backend.acquire(second, mode=LockMode.SHARED, blocking=False)
                backend.release(first)
                backend.acquire(second, mode=LockMode.SHARED, blocking=False)
                backend.release(second)
            finally:
                os.close(second)
                os.close(first)

    def test_native_independent_process_shared_locks_are_compatible(self) -> None:
        with TemporaryDirectory() as raw:
            path = Path(raw) / "shared-lock.bin"
            path.write_bytes(b"lock")
            descriptor = os.open(path, os.O_RDWR)
            backend = WindowsCrossProcessLockingBackend()
            try:
                backend.acquire(descriptor, mode=LockMode.SHARED)
                result = self._run_lock_child(
                    path,
                    mode=LockMode.SHARED,
                    blocking=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), ["attempting", "acquired"])
            finally:
                backend.release(descriptor)
                os.close(descriptor)

    def test_native_independent_process_exclusive_nonblocking_contends(self) -> None:
        with TemporaryDirectory() as raw:
            path = Path(raw) / "exclusive-contention.bin"
            path.write_bytes(b"lock")
            descriptor = os.open(path, os.O_RDWR)
            backend = WindowsCrossProcessLockingBackend()
            try:
                backend.acquire(descriptor, mode=LockMode.SHARED)
                result = self._run_lock_child(
                    path,
                    mode=LockMode.EXCLUSIVE,
                    blocking=False,
                )
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertEqual(result.stdout.splitlines(), ["attempting", "blocked"])
            finally:
                backend.release(descriptor)
                os.close(descriptor)

    def test_native_independent_process_blocking_waiter_acquires_after_release(
        self,
    ) -> None:
        with TemporaryDirectory() as raw:
            path = Path(raw) / "blocking-waiter.bin"
            path.write_bytes(b"lock")
            descriptor = os.open(path, os.O_RDWR)
            backend = WindowsCrossProcessLockingBackend()
            process: subprocess.Popen[str] | None = None
            locked = False
            try:
                backend.acquire(descriptor, mode=LockMode.EXCLUSIVE)
                locked = True
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-u",
                        "-c",
                        _LOCK_CHILD_SCRIPT,
                        str(path),
                        LockMode.EXCLUSIVE.value,
                        "blocking",
                    ],
                    cwd=ROOT,
                    env=_subprocess_environment(),
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if process.stdout is None:
                    self.fail("blocking lock child stdout pipe is unavailable")
                self.assertEqual(process.stdout.readline().strip(), "attempting")
                with self.assertRaises(subprocess.TimeoutExpired):
                    process.wait(timeout=1)
                backend.release(descriptor)
                locked = False
                stdout, stderr = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(stdout.splitlines(), ["acquired"])
            finally:
                if locked:
                    backend.release(descriptor)
                if process is not None and process.poll() is None:
                    process.kill()
                    process.communicate(timeout=15)
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
