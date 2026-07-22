from pathlib import Path

import pytest

import build
from patches import get_source_patches

FIXTURE_DIR = Path("tests/fixtures/frida-17.16.3")


def apply_text_patches(text: str, name: str) -> str:
    for old, new in get_source_patches(name, name.capitalize()):
        text = text.replace(old, new)
    return text


def make_core_fixture(tmp_path: Path) -> Path:
    core = tmp_path / "subprojects" / "frida-core"
    linux = core / "src" / "linux"
    helpers = linux / "helpers"
    helpers.mkdir(parents=True)
    (linux / "linux-host-session.vala").write_text(
        (FIXTURE_DIR / "linux-host-session.vala").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (helpers / "zymbiote.c").write_text(
        (FIXTURE_DIR / "zymbiote.c").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (core / "lib/base").mkdir(parents=True)
    (core / "lib/base/session.vala").write_text(
        "The frida-server is not running.\n"
        'throw new Error ("Unable to communicate with remote frida-server");\n',
        encoding="utf-8",
    )
    (core / "src/socket").mkdir(parents=True)
    (core / "src/socket/socket-host-session.vala").write_text(
        "\n".join(["frida-server"] * 4),
        encoding="utf-8",
    )
    exit_monitor = core / "lib/payload/exit-monitor.vala"
    exit_monitor.parent.mkdir(parents=True)
    exit_monitor.write_text(
        (FIXTURE_DIR / "exit-monitor.vala").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    exceptor = tmp_path / "subprojects/frida-gum/gum/backend-posix/gumexceptor-posix.c"
    exceptor.parent.mkdir(parents=True)
    exceptor.write_text(
        (FIXTURE_DIR / "gumexceptor-posix.c").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    runtime_sources = {
        "subprojects/frida-core/lib/base/rpc.vala": """namespace Frida {
\tpublic sealed class RpcClient : Object {
\t\tvoid build_request (Json.Builder request) {
\t\t\trequest.add_string_value (\"frida:rpc\");
\t\t}
\t\tbool inspect (string json, string? type) {
\t\t\tif (json.index_of (\"\\\"frida:rpc\\\"\") == -1)
\t\t\t\treturn false;
\t\t\tif (type == null || type != \"frida:rpc\")
\t\t\t\treturn false;
\t\t\treturn true;
\t\t}
\t\tprivate class PendingResponse {
\t\t}
\t}
}
""",
        "subprojects/frida-core/src/barebone/script-runtime/message-dispatcher.ts": (
            "export class MessageDispatcher {\n"
            "  dispatch(message) {\n"
            '    if (message[0] === "frida:rpc") {\n'
            '      send(["frida:rpc"]);\n'
            '      send(["frida:rpc"]);\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
        "subprojects/frida-gum/bindings/gumjs/runtime/message-dispatcher.js": (
            "export function MessageDispatcher() {\n"
            "  if (message[0] === 'frida:rpc') {\n"
            "    send(['frida:rpc']);\n"
            "    send(['frida:rpc']);\n"
            "    send(['frida:rpc']);\n"
            "  }\n"
            "}\n"
        ),
        "subprojects/frida-gum/bindings/gumjs/runtime/worker.js": (
            "export class Worker {\n"
            "  request(payload) {\n"
            "    if (payload[0] === 'frida:rpc') this.post(['frida:rpc']);\n"
            "  }\n"
            "}\n"
        ),
        "subprojects/frida-core/lib/gadget/gadget-glue.c": (
            'worker_thread = g_thread_new ("frida-gadget", run_worker_loop, NULL);\n'
        ),
        "subprojects/frida-core/lib/gadget/gadget.vala": (
            'Environment.set_thread_name ("frida-gadget-tcp-%u".printf (listen_port));\n'
            'Environment.set_thread_name ("frida-gadget-unix");\n'
        ),
        "subprojects/frida-core/lib/agent/agent.vala": (
            'new Thread<bool> ("frida-eternal-agent", callback);\n' * 3
        ),
        "subprojects/frida-core/lib/base/p2p.vala": (
            'new Thread<bool> ("frida-generate-certificate", callback);\n'
        ),
        "subprojects/frida-core/lib/base/socket.vala": (
            'headers.replace ("User-Agent", "Frida/" + version);\n' * 3
        ),
        "subprojects/frida-core/src/frida-glue.c": (
            'main_thread = g_thread_new ("frida-main-loop", run_main_loop, NULL);\n'
        ),
        "subprojects/frida-core/lib/payload/portal-client.vala": (
            'throw new Error.NOT_SUPPORTED ("unsupported by frida-gadget");\n'
        ),
        "subprojects/frida-core/src/droidy/injector.vala": (
            'string so_path = "/data/local/tmp/frida-gadget-id.so";\n'
            'string config_path = "/data/local/tmp/frida-gadget-id.config";\n'
        ),
        "subprojects/frida-core/src/droidy/droidy-host-session.vala": (
            'throw new Error.NOT_SUPPORTED ("frida-gadget.so to use");\n'
        ),
    }
    for relative_path, content in runtime_sources.items():
        target = tmp_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return tmp_path


def test_global_patches_preserve_upstream_glib_flavor_fixture() -> None:
    source = (FIXTURE_DIR / "compat-meson.build").read_text(encoding="utf-8")
    assert apply_text_patches(source, "oemcodec") == source


@pytest.mark.parametrize(
    "identifier",
    ['"/re/frida/GadgetSession"', '"re.frida.HostSession"', '"Frida"'],
)
def test_global_patches_preserve_stock_client_identifiers(identifier: str) -> None:
    assert apply_text_patches(identifier, "oemcodec") == identifier


def test_required_patches_rename_jni_and_every_zymbiote_template(tmp_path: Path) -> None:
    root = make_core_fixture(tmp_path)

    build.apply_required_file_patches(root, "oemcodec")

    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in root.rglob("*.*") if path.is_file()
    )
    assert "re/frida/HelperBackend" not in combined
    assert "/frida-zymbiote-" not in combined
    assert "re/oemcodec/HelperBackend" in combined
    assert combined.count("/oemcodec-zymbiote-") == 3
    assert "frida-server" not in combined
    assert combined.count("oemcodec-server") == 6
    assert "interceptor.attach" not in combined
    assert "gum_exceptor_backend_replacement_signal, NULL" not in combined
    assert "Signal interception intentionally disabled" in combined


def test_required_patch_fails_when_upstream_contract_drifts(tmp_path: Path) -> None:
    root = make_core_fixture(tmp_path)
    target = root / "subprojects/frida-core/src/linux/linux-host-session.vala"
    target.write_text(
        target.read_text(encoding="utf-8").replace(
            "re/frida/HelperBackend", "changed/upstream/Class"
        ),
        encoding="utf-8",
    )

    with pytest.raises(build.BuildError, match="re/frida/HelperBackend"):
        build.apply_required_file_patches(root, "oemcodec")


def test_required_patches_remove_runtime_rpc_branding_and_thread_markers(tmp_path: Path) -> None:
    root = make_core_fixture(tmp_path)

    build.apply_required_file_patches(root, "oemcodec")

    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in root.rglob("*.*") if path.is_file()
    )
    for marker in (
        "frida:rpc",
        "frida-gadget",
        "frida-eternal-agent",
        "frida-generate-certificate",
        "frida-main-loop",
        "Frida/",
    ):
        assert marker not in combined
    assert "String.fromCharCode(102, 114, 105, 100, 97, 58, 114, 112, 99)" in combined
    assert "make_rpc_tag" in combined
    assert "oemcodec-gadget" in combined
    assert "Oemcodec/" in combined


def test_targeted_patch_uses_non_counted_art_jit_memfd_name(tmp_path: Path) -> None:
    root = make_core_fixture(tmp_path)
    linux = root / "subprojects/frida-core/lib/base/linux.vala"
    linux.write_text(
        "return Linux.syscall (LinuxSyscall.MEMFD_CREATE, name, flags);\n",
        encoding="utf-8",
    )

    build.apply_targeted_patches(root, "oemcodec", 17)

    patched = linux.read_text(encoding="utf-8")
    assert '"jit-code-cache"' in patched
    assert '"jit-cache"' not in patched


def test_zymbiote_artifacts_patch_the_fixed_socket_field(tmp_path: Path) -> None:
    root = make_core_fixture(tmp_path)
    old_socket = b"/frida-zymbiote-" + (b"0" * 32)
    old_field = old_socket.ljust(64, b"\0")
    artifacts = root / "subprojects/frida-core/src/linux/helpers/artifacts/native"
    for architecture in ("arm", "arm64", "x86", "x86_64"):
        target = artifacts / architecture / "zymbiote.elf"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"ELF-prefix" + old_field + b"ELF-suffix")

    build.patch_zymbiote_artifacts(root, "oemcodec")

    expected_socket = b"/oemcodec-zymbiote-" + (b"0" * 32)
    expected_field = expected_socket.ljust(64, b"\0")
    for target in artifacts.glob("*/zymbiote.elf"):
        data = target.read_bytes()
        assert len(data) == len(b"ELF-prefix" + old_field + b"ELF-suffix")
        assert old_socket not in data
        assert expected_field in data


def test_zymbiote_artifacts_fail_when_upstream_binary_drifts(tmp_path: Path) -> None:
    root = make_core_fixture(tmp_path)
    artifacts = root / "subprojects/frida-core/src/linux/helpers/artifacts/native"
    for architecture in ("arm", "arm64", "x86", "x86_64"):
        target = artifacts / architecture / "zymbiote.elf"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"unexpected")

    with pytest.raises(build.BuildError, match="arm/zymbiote.elf"):
        build.patch_zymbiote_artifacts(root, "oemcodec")
