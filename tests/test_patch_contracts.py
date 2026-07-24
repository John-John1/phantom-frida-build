# ruff: noqa: E501

from pathlib import Path

import pytest

import build
from patches import get_source_patches

FIXTURE_DIR = Path("tests/fixtures/frida-17.16.4")


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
        "subprojects/frida-core/src/host-session-service.vala": (
            'e = new Error.PROCESS_NOT_RESPONDING ("Process with pid %u either refused to load '
            'frida-agent, " +\n'
            '    "or terminated during injection", pid);\n'
        ),
        "subprojects/frida-gum/bindings/gumjs/guminspectorserver.c": (
            'json_builder_add_string_value (builder, "Frida/v" FRIDA_VERSION);\n'
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
        "frida-agent",
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


def make_strict_wx_fixture(
    tmp_path: Path,
) -> tuple[Path, dict[str, Path], list[Path]]:
    root = make_core_fixture(tmp_path)
    paths = {
        "memory": root / "subprojects/frida-gum/gum/gummemory.c",
        "allocator": root / "subprojects/frida-gum/gum/gumcodeallocator.c",
        "helper_backend": (root / "subprojects/frida-core/src/linux/frida-helper-backend.vala"),
        "bootstrapper": (root / "subprojects/frida-core/src/linux/helpers/bootstrapper.c"),
        "inject_context": (root / "subprojects/frida-core/src/linux/helpers/inject-context.h"),
        "proc_mem": (root / "subprojects/frida-core/src/linux/proc-mem-injector.vala"),
    }
    stalkers = [
        root / "subprojects/frida-gum/gum/backend-arm/gumstalker-arm.c",
        root / "subprojects/frida-gum/gum/backend-arm64/gumstalker-arm64.c",
        root / "subprojects/frida-gum/gum/backend-x86/gumstalker-x86.c",
    ]
    paths["memory"].parent.mkdir(parents=True, exist_ok=True)
    paths["allocator"].parent.mkdir(parents=True, exist_ok=True)
    paths["memory"].write_text(
        """GumRwxSupport
gum_query_rwx_support (void)
{
#if defined (HAVE_DARWIN) && !defined (HAVE_I386)
  return GUM_RWX_NONE;
#else
  return GUM_RWX_FULL;
#endif
}

      restored = ((original_protections[i] & GUM_PAGE_WRITE) != 0)
          ? GUM_PAGE_RWX
          : GUM_PAGE_RX;
""",
        encoding="utf-8",
    )
    paths["allocator"].write_text(
        """G_DEFINE_BOXED_TYPE (GumCodeSlice, gum_code_slice, gum_code_slice_ref,
                     gum_code_slice_unref)
G_DEFINE_BOXED_TYPE (GumCodeDeflector, gum_code_deflector,
                     gum_code_deflector_ref, gum_code_deflector_unref)

void
gum_code_allocator_init (GumCodeAllocator * allocator,
                         gsize slice_size)
{
  rwx_supported = gum_query_is_rwx_supported ();
  rwx_supported = gum_query_is_rwx_supported ();
  if (gum_query_is_rwx_supported ())
    return;
}
""",
        encoding="utf-8",
    )
    for stalker in stalkers:
        stalker.parent.mkdir(parents=True, exist_ok=True)
        stalker.write_text(
            "  self->is_rwx_supported = gum_query_rwx_support () != GUM_RWX_NONE;\n",
            encoding="utf-8",
        )
    paths["helper_backend"].write_text(
        """		private static uint64 mmap_offset;
		private static uint64 munmap_offset;

			mmap_offset = (uint64) (uintptr) libc.find_export_by_name ("mmap") - local_libc.start;
			munmap_offset = (uint64) (uintptr) libc.find_export_by_name ("munmap") - local_libc.start;

			uint64 loader_base = (uintptr) bres.context.allocation_base;
			GPRegs regs = saved_regs;

			uint64 remote_mmap = 0;
			uint64 remote_munmap = 0;

			if (same_libc) {
				remote_mmap = remote_libc.start + mmap_offset;
				remote_munmap = remote_libc.start + munmap_offset;
			}

			if (remote_mmap != 0) {
				allocation_base = yield allocate_memory (remote_mmap, allocation_size,
					Posix.PROT_READ | Posix.PROT_WRITE | Posix.PROT_EXEC, cancellable);
			} else {

				bootstrap_ctx.allocation_size = allocation_size;
				write_memory (bootstrap_ctx_location, (uint8[]) &bootstrap_ctx);

					bootstrap_ctx.allocation_size = allocation_size;
					bootstrap_ctx.page_size = Gum.query_page_size ();

	protected struct HelperBootstrapContext {
		void * allocation_base;
		size_t allocation_size;

		size_t page_size;
	}

	protected struct HelperLibcApi {
		void * printf;
		void * sprintf;

		void * mmap;
		void * munmap;
	}

		public async uint64 allocate_memory (uint64 mmap_impl, size_t size, int prot, Cancellable? cancellable)
				throws Error, IOError {
			var builder = new RemoteCallBuilder (mmap_impl, saved_regs);
			RemoteCallResult res = yield builder.build (this).execute (cancellable);
			if (res.return_value == MAP_FAILED)
				throw new Error.NOT_SUPPORTED ("Unexpected failure while trying to allocate memory");
			return res.return_value;
		}

		public async void deallocate_memory (uint64 munmap_impl, uint64 address, size_t size, Cancellable? cancellable)
""",
        encoding="utf-8",
    )
    paths["bootstrapper"].write_text(
        """static int frida_socketpair (int domain, int type, int protocol, int sv[2]);
static int frida_prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

  if (ctx->allocation_base == NULL)
  {
    ctx->allocation_base = mmap (NULL, ctx->allocation_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (ctx->allocation_base == MAP_FAILED)
        ? FRIDA_BOOTSTRAP_ALLOCATION_ERROR
        : FRIDA_BOOTSTRAP_ALLOCATION_SUCCESS;
  }

  ctx.total_missing = 17;

  FRIDA_TRY_COLLECT (mmap)
  FRIDA_TRY_COLLECT (munmap)

static int
frida_socketpair (int domain, int type, int protocol, int sv[2])
""",
        encoding="utf-8",
    )
    paths["inject_context"].write_text(
        """struct _FridaBootstrapContext
{
  void * allocation_base;
  size_t allocation_size;

  size_t page_size;
};

struct _FridaLibcApi
{
  int (* printf) (const char * format, ...);
  int (* sprintf) (char * str, const char * format, ...);

  void * (* mmap) (void * addr, size_t length, int prot, int flags, int fd, off_t offset);
  int (* munmap) (void * addr, size_t length);
};
""",
        encoding="utf-8",
    )
    paths["proc_mem"].write_text(
        """			api.table.mmap = resolve_one (remote_maps, "mmap");
			api.table.munmap = resolve_one (remote_maps, "munmap");
""",
        encoding="utf-8",
    )
    return root, paths, stalkers


def test_strict_wx_patch_limits_non_rwx_mode_to_persistent_android_code_pools(
    tmp_path: Path,
) -> None:
    root, paths, stalkers = make_strict_wx_fixture(tmp_path)

    build.apply_strict_wx_patch(root, "frida")

    patched_memory = paths["memory"].read_text(encoding="utf-8")
    patched_allocator = paths["allocator"].read_text(encoding="utf-8")
    assert "#if defined (HAVE_DARWIN) && !defined (HAVE_I386)" in patched_memory
    assert "|| defined (HAVE_ANDROID)" not in patched_memory
    assert "#if defined (HAVE_ANDROID)" in patched_memory
    assert "original_protections[i] & GUM_PAGE_EXECUTE" in patched_memory
    assert "? GUM_PAGE_RWX" in patched_memory
    assert "gum_code_allocator_is_rwx_supported" in patched_allocator
    assert patched_allocator.count("gum_query_is_rwx_supported ()") == 1
    for stalker in stalkers:
        patched_stalker = stalker.read_text(encoding="utf-8")
        assert "self->is_rwx_supported = FALSE;" in patched_stalker
        assert "#if defined (HAVE_ANDROID)" in patched_stalker


def test_strict_wx_patch_splits_android_bootstrap_code_data_and_stack(
    tmp_path: Path,
) -> None:
    root, paths, _ = make_strict_wx_fixture(tmp_path)

    build.apply_strict_wx_patch(root, "frida")

    backend = paths["helper_backend"].read_text(encoding="utf-8")
    bootstrapper = paths["bootstrapper"].read_text(encoding="utf-8")
    context = paths["inject_context"].read_text(encoding="utf-8")
    proc_mem = paths["proc_mem"].read_text(encoding="utf-8")

    assert "mprotect_offset" in backend
    assert "yield protect_memory" in backend
    assert "loader_base + loader_layout.ctx_offset" in backend
    assert "allocation_base + allocation_size - stack_size" in backend
    assert "Posix.PROT_READ | Posix.PROT_EXEC" in backend
    assert "Posix.PROT_READ | Posix.PROT_WRITE | Posix.PROT_EXEC" in backend
    assert backend.count("bootstrap_ctx.stack_size = stack_size;") == 2
    assert "#if ANDROID" in backend

    assert "#ifdef __ANDROID__" in bootstrapper
    assert "frida_mprotect" in bootstrapper
    assert "PROT_READ | PROT_EXEC" in bootstrapper
    assert "PROT_READ | PROT_WRITE | PROT_EXEC" in bootstrapper
    assert "ctx.total_missing = 18;" in bootstrapper
    assert "FRIDA_TRY_COLLECT (mprotect)" in bootstrapper

    assert "size_t stack_size;" in context
    assert "int (* mprotect)" in context
    assert "void * mprotect;" in backend
    assert 'api.table.mprotect = resolve_one (remote_maps, "mprotect");' in proc_mem


def test_strict_wx_patch_uses_the_renamed_helper_backend(tmp_path: Path) -> None:
    root, paths, _ = make_strict_wx_fixture(tmp_path)
    renamed_backend = paths["helper_backend"].with_name("oemcodec-helper-backend.vala")
    build.rename_frida_files(root, "oemcodec")

    build.apply_strict_wx_patch(root, "oemcodec")

    assert not paths["helper_backend"].exists()
    assert "mprotect_offset" in renamed_backend.read_text(encoding="utf-8")


def test_strict_wx_patch_rejects_allocator_source_drift(tmp_path: Path) -> None:
    root, paths, _ = make_strict_wx_fixture(tmp_path)
    allocator = paths["allocator"]
    allocator.write_text("changed upstream allocator\n", encoding="utf-8")

    with pytest.raises(build.BuildError, match="gumcodeallocator.c"):
        build.apply_strict_wx_patch(root, "frida")


def test_strict_wx_patch_rejects_android_injector_source_drift(
    tmp_path: Path,
) -> None:
    root, paths, _ = make_strict_wx_fixture(tmp_path)
    paths["bootstrapper"].write_text("changed upstream bootstrapper\n", encoding="utf-8")

    with pytest.raises(build.BuildError, match="bootstrapper.c"):
        build.apply_strict_wx_patch(root, "frida")


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
