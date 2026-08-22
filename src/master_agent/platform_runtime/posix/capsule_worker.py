"""Restricted child process for pure capability-capsule execution.

This file is launched with an isolated Python interpreter.  It deliberately
has no dependency on the MasterAgent package so the host can expose only one
bounded JSON request/response protocol inside an OS sandbox.
"""

from __future__ import annotations

import ast
import json
import resource
import sys
from types import MappingProxyType
from typing import Any

WORKER_PROTOCOL = "master-agent/capsule-worker@1"
_MAX_ENVELOPE_BYTES = 2 * 1024 * 1024
_MAX_AST_NODES = 8_192
_MAX_SOURCE_CHARACTERS = 256 * 1024
_SAFE_CALLS = frozenset(
    {
        "abs",
        "all",
        "any",
        "bool",
        "dict",
        "enumerate",
        "float",
        "int",
        "len",
        "list",
        "max",
        "min",
        "range",
        "reversed",
        "round",
        "sorted",
        "str",
        "sum",
        "tuple",
        "zip",
    }
)
_SAFE_METHODS = frozenset(
    {
        "casefold",
        "copy",
        "count",
        "endswith",
        "get",
        "index",
        "items",
        "join",
        "keys",
        "lower",
        "replace",
        "split",
        "startswith",
        "strip",
        "upper",
        "values",
    }
)
_FORBIDDEN_NODES = (
    ast.AsyncFor,
    ast.AsyncFunctionDef,
    ast.AsyncWith,
    ast.Await,
    ast.ClassDef,
    ast.Delete,
    ast.Global,
    ast.Import,
    ast.ImportFrom,
    ast.Lambda,
    ast.NamedExpr,
    ast.Nonlocal,
    ast.Raise,
    ast.Try,
    ast.With,
    ast.Yield,
    ast.YieldFrom,
)


class CapsuleProgramRejected(Exception):
    """Raised for source outside the pure capsule language subset."""


class _ProgramValidator(ast.NodeVisitor):
    def __init__(self) -> None:
        self.functions: set[str] = set()
        self.node_count = 0

    def visit(self, node: ast.AST) -> Any:
        self.node_count += 1
        if self.node_count > _MAX_AST_NODES:
            raise CapsuleProgramRejected("source_too_complex")
        if isinstance(node, _FORBIDDEN_NODES):
            raise CapsuleProgramRejected("forbidden_syntax")
        return super().visit(node)

    def visit_Module(self, node: ast.Module) -> None:
        for item in node.body:
            if (
                isinstance(item, ast.Expr)
                and isinstance(item.value, ast.Constant)
                and isinstance(item.value.value, str)
            ):
                continue
            if not isinstance(item, ast.FunctionDef):
                raise CapsuleProgramRejected("top_level_statement")
            self.functions.add(item.name)
        if "run" not in self.functions:
            raise CapsuleProgramRejected("missing_run")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if (
            not node.name.isidentifier()
            or node.name.startswith("_")
            or node.decorator_list
            or node.returns is not None
            or node.type_comment is not None
        ):
            raise CapsuleProgramRejected("unsafe_function")
        arguments = node.args
        if (
            arguments.posonlyargs
            or arguments.kwonlyargs
            or arguments.vararg is not None
            or arguments.kwarg is not None
            or arguments.defaults
            or arguments.kw_defaults
            or any(argument.annotation is not None for argument in arguments.args)
        ):
            raise CapsuleProgramRejected("unsafe_function_signature")
        if node.name == "run" and len(arguments.args) != 1:
            raise CapsuleProgramRejected("run_signature")
        if node.name != "run" and len(arguments.args) > 8:
            raise CapsuleProgramRejected("helper_signature")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id.startswith("_"):
            raise CapsuleProgramRejected("private_name")

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr not in _SAFE_METHODS:
            raise CapsuleProgramRejected("unsafe_attribute")
        self.visit(node.value)

    def visit_Call(self, node: ast.Call) -> None:
        if any(keyword.arg is None for keyword in node.keywords):
            raise CapsuleProgramRejected("expanded_call")
        if isinstance(node.func, ast.Name):
            if node.func.id not in _SAFE_CALLS and node.func.id not in self.functions:
                raise CapsuleProgramRejected("unsafe_call")
            self.visit(node.func)
        elif isinstance(node.func, ast.Attribute):
            self.visit(node.func)
        else:
            raise CapsuleProgramRejected("dynamic_call")
        for argument in node.args:
            if isinstance(argument, ast.Starred):
                raise CapsuleProgramRejected("expanded_call")
            self.visit(argument)
        for keyword in node.keywords:
            self.visit(keyword.value)

    def visit_Constant(self, node: ast.Constant) -> None:
        if not isinstance(node.value, (str, int, float, bool, type(None))):
            raise CapsuleProgramRejected("non_json_constant")


def _read_envelope() -> dict[str, Any]:
    payload = sys.stdin.buffer.read(_MAX_ENVELOPE_BYTES + 1)
    if len(payload) > _MAX_ENVELOPE_BYTES:
        raise CapsuleProgramRejected("envelope_too_large")
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise CapsuleProgramRejected("envelope_not_object")
    return value


def _validate_source(source: str) -> ast.Module:
    if not source or len(source) > _MAX_SOURCE_CHARACTERS:
        raise CapsuleProgramRejected("source_size")
    try:
        tree = ast.parse(source, filename="<capability-capsule>", mode="exec")
    except SyntaxError as error:
        raise CapsuleProgramRejected("source_syntax") from error
    _ProgramValidator().visit(tree)
    return tree


def _apply_limits(limits: dict[str, Any]) -> None:
    required = {
        "cpu_seconds",
        "memory_bytes",
        "max_processes",
        "max_output_bytes",
    }
    if set(limits) != required:
        raise CapsuleProgramRejected("limit_contract")
    parsed: dict[str, int] = {}
    for name in required:
        value = limits[name]
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise CapsuleProgramRejected("limit_value")
        parsed[name] = value
    _set_limit(resource.RLIMIT_CPU, parsed["cpu_seconds"])
    _set_limit(resource.RLIMIT_AS, parsed["memory_bytes"])
    _set_limit(resource.RLIMIT_NPROC, parsed["max_processes"])
    _set_limit(resource.RLIMIT_NOFILE, 16)
    _set_limit(resource.RLIMIT_FSIZE, parsed["max_output_bytes"] + 4_096)
    _set_limit(resource.RLIMIT_CORE, 0)


def _set_limit(kind: int, value: int) -> None:
    resource.setrlimit(kind, (value, value))


def _deny_ambient_authority(event: str, _arguments: tuple[Any, ...]) -> None:
    denied = (
        "ctypes.",
        "import",
        "marshal.",
        "open",
        "os.exec",
        "os.fork",
        "os.posix_spawn",
        "os.spawn",
        "os.system",
        "socket.",
        "subprocess.",
    )
    if event == "open" or event.startswith(denied):
        raise PermissionError("capsule ambient authority denied")


def _safe_builtins() -> dict[str, object]:
    selected = {
        name: getattr(__builtins__, name)
        for name in _SAFE_CALLS
        if hasattr(__builtins__, name)
    }
    # ``__builtins__`` is a dict in some launch modes.
    if len(selected) != len(_SAFE_CALLS):
        source = __builtins__
        if isinstance(source, dict):
            selected = {name: source[name] for name in _SAFE_CALLS}
    return selected


def _execute(envelope: dict[str, Any]) -> dict[str, Any]:
    if envelope.get("schema") != WORKER_PROTOCOL:
        raise CapsuleProgramRejected("protocol")
    source = envelope.get("source")
    request = envelope.get("request")
    limits = envelope.get("limits")
    if not isinstance(source, str) or not isinstance(request, dict):
        raise CapsuleProgramRejected("request_contract")
    if not isinstance(limits, dict):
        raise CapsuleProgramRejected("limit_contract")
    _apply_limits(limits)
    tree = _validate_source(source)
    code = compile(tree, "<capability-capsule>", "exec", dont_inherit=True, optimize=2)
    sys.addaudithook(_deny_ambient_authority)
    namespace: dict[str, object] = {"__builtins__": MappingProxyType(_safe_builtins())}
    # The AST allowlist above is the capsule language boundary.  Execution is
    # intentionally confined to the restricted namespace and child process.
    exec(code, namespace, namespace)  # nosec B102  # noqa: S102
    runner = namespace.get("run")
    if not callable(runner):
        raise CapsuleProgramRejected("missing_run")
    output = runner(request)
    if not isinstance(output, dict):
        raise CapsuleProgramRejected("output_not_object")
    encoded = json.dumps(
        output,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > int(limits["max_output_bytes"]):
        raise CapsuleProgramRejected("output_too_large")
    return {"schema": WORKER_PROTOCOL, "ok": True, "output": output}


def main() -> int:
    try:
        response = _execute(_read_envelope())
    except CapsuleProgramRejected as error:
        response = {
            "schema": WORKER_PROTOCOL,
            "ok": False,
            "error": str(error),
        }
    except Exception as error:  # noqa: BLE001 - sanitize every capsule failure.
        # Never echo exception text: it may contain input content.
        response = {
            "schema": WORKER_PROTOCOL,
            "ok": False,
            "error": f"runtime_{type(error).__name__}",
        }
    payload = json.dumps(
        response,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()
    return 0 if response.get("ok") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
