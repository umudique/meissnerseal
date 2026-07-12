// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::expect_used, clippy::panic)]

use std::{
    path::Path,
    process::{Command, Output, Stdio},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use tempfile::TempDir;

const PASSWORD: &[u8] = b"e2e-test-password-never-real";
const EXPORT_PASS: &[u8] = b"e2e-export-passphrase-never-real";
const SECRET_VALUE: &str = "e2e-secret-value-never-real";
const CLI_TIMEOUT: Duration = Duration::from_secs(30);

struct TestEnv {
    temp: TempDir,
}

impl TestEnv {
    fn new() -> Self {
        Self {
            temp: TempDir::new().expect("tempdir"),
        }
    }

    fn path(&self) -> &Path {
        self.temp.path()
    }
}

#[test]
fn init_creates_msv_vault_file() {
    let env = TestEnv::new();
    let vault = env.path().join("init-ok.msv");

    let output = run_cli(&env, ["init", path_str(&vault)], &[PASSWORD, PASSWORD]);

    assert_success(&output);
    assert!(vault.exists());
    assert_eq!(vault.extension().and_then(|ext| ext.to_str()), Some("msv"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&vault)
            .expect("vault metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn add_then_list_shows_item_without_secret() {
    let env = TestEnv::new();
    let vault = env.path().join("add-list.msv");
    init_vault(&env, &vault);

    let add = run_cli(
        &env,
        [
            "add",
            "--label",
            "CI token",
            "--kind",
            "api-token",
            "--vault",
            path_str(&vault),
        ],
        &[PASSWORD, SECRET_VALUE.as_bytes()],
    );
    assert_success(&add);

    let list = run_cli(&env, ["list", path_str(&vault)], &[PASSWORD]);
    assert_success(&list);
    assert_no_secret_leak(&list);
    let stdout = stdout(&list);
    assert!(stdout.contains("CI token"));
    assert!(stdout.contains("ApiToken"));
    assert!(!stdout.contains(SECRET_VALUE));
}

#[test]
fn add_then_get_uses_opaque_id_and_note_precedes_secret() {
    let env = TestEnv::new();
    let vault = env.path().join("add-get.msv");
    init_vault(&env, &vault);
    let item_id = add_item(&env, &vault, "operator note");

    let output = run_cli(
        &env,
        ["get", &item_id, "--vault", path_str(&vault)],
        &[PASSWORD],
    );

    assert_success(&output);
    let stdout = stdout(&output);
    let note = stdout
        .find("NOTE: secret printed to stdout")
        .expect("note line");
    let secret = stdout.find(SECRET_VALUE).expect("secret line");
    assert!(note < secret);
    assert!(!stdout.contains("operator note"));
}

#[test]
fn export_writes_nonempty_msexp_bundle() {
    let env = TestEnv::new();
    let vault = env.path().join("export-source.msv");
    let bundle = env.path().join("exported.msexp");
    init_vault(&env, &vault);
    let _ = add_item(&env, &vault, "exported note");

    let output = run_cli(
        &env,
        [
            "export",
            "--output",
            path_str(&bundle),
            "--vault",
            path_str(&vault),
        ],
        &[PASSWORD, EXPORT_PASS],
    );

    assert_success(&output);
    assert_no_secret_leak(&output);
    assert_eq!(
        bundle.extension().and_then(|ext| ext.to_str()),
        Some("msexp")
    );
    let metadata = std::fs::metadata(&bundle).expect("bundle metadata");
    assert!(metadata.len() > 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "export bundle must have mode 0600");
    }
    let bytes = std::fs::read(&bundle).expect("bundle bytes");
    assert!(!contains_subslice(&bytes, SECRET_VALUE.as_bytes()));
    assert!(!contains_subslice(&bytes, b"exported note"), "label must not appear in bundle plaintext");
    let header_prefix = bytes.get(..bytes.len().min(16)).expect("bundle prefix");
    assert!(!contains_subslice(header_prefix, b"ARCEXP"));
    assert!(contains_subslice(&bytes, b"MSEXP"));
}

#[test]
fn export_then_import_roundtrips_item() {
    let env = TestEnv::new();
    let source = env.path().join("source.msv");
    let dest = env.path().join("dest.msv");
    let bundle = env.path().join("roundtrip.msexp");
    init_vault(&env, &source);
    init_vault(&env, &dest);
    let _ = add_item(&env, &source, "roundtrip item");

    let export = run_cli(
        &env,
        [
            "export",
            "--output",
            path_str(&bundle),
            "--vault",
            path_str(&source),
        ],
        &[PASSWORD, EXPORT_PASS],
    );
    assert_success(&export);

    let import = run_cli(
        &env,
        [
            "import",
            "--input",
            path_str(&bundle),
            "--vault",
            path_str(&dest),
        ],
        &[PASSWORD, EXPORT_PASS],
    );
    assert_success(&import);
    let import_stdout = stdout(&import);
    let imported_id = import_stdout
        .lines()
        .map(str::trim)
        .find(|line| is_opaque_item_id_hex32(line))
        .expect("imported item id line");

    let list = run_cli(&env, ["list", path_str(&dest)], &[PASSWORD]);
    assert_success(&list);
    let list_stdout = stdout(&list);
    assert!(list_stdout.contains("roundtrip item"));
    assert!(!list_stdout.contains(SECRET_VALUE));

    let get = run_cli(
        &env,
        ["get", imported_id, "--vault", path_str(&dest)],
        &[PASSWORD],
    );
    assert_success(&get);
    assert!(stdout(&get).contains(SECRET_VALUE));
}

#[test]
fn import_rejects_wrong_passphrase() {
    let env = TestEnv::new();
    let source = env.path().join("wrong-pass-source.msv");
    let dest = env.path().join("wrong-pass-dest.msv");
    let bundle = env.path().join("wrong-pass.msexp");
    init_vault(&env, &source);
    init_vault(&env, &dest);
    let _ = add_item(&env, &source, "wrong pass import item");

    let export = run_cli(
        &env,
        [
            "export",
            "--output",
            path_str(&bundle),
            "--vault",
            path_str(&source),
        ],
        &[PASSWORD, EXPORT_PASS],
    );
    assert_success(&export);

    let import = run_cli(
        &env,
        [
            "import",
            "--input",
            path_str(&bundle),
            "--vault",
            path_str(&dest),
        ],
        &[PASSWORD, b"wrong-export-passphrase-never-real"],
    );

    assert!(!import.status.success());
    assert_no_secret_leak(&import);

    let list = run_cli(&env, ["list", path_str(&dest)], &[PASSWORD]);
    assert_success(&list);
    let stdout = stdout(&list);
    assert!(!stdout.contains("wrong pass import item"));
    assert!(!stdout.contains(SECRET_VALUE));
}

#[test]
fn lock_returns_ok() {
    let env = TestEnv::new();
    let output = run_cli(&env, ["lock"], &[]);

    assert_success(&output);
    assert!(stdout(&output).contains("Vault is locked."));
}

#[test]
fn transfer_and_device_stubs_error_at_runtime() {
    let env = TestEnv::new();
    let transfer = run_cli(&env, ["transfer", "create"], &[]);
    assert!(!transfer.status.success());
    assert!(stderr(&transfer).contains("command is not wired in MVP-0 CLI yet"));

    let device = run_cli(&env, ["device", "list"], &[]);
    assert!(!device.status.success());
    assert!(stderr(&device).contains("command is not wired in MVP-0 CLI yet"));
}

#[test]
fn get_with_wrong_item_id_returns_err() {
    let env = TestEnv::new();
    let vault = env.path().join("wrong-id.msv");
    init_vault(&env, &vault);
    let _ = add_item(&env, &vault, "wrong id item");

    let output = run_cli(
        &env,
        [
            "get",
            "00000000000000000000000000000000",
            "--vault",
            path_str(&vault),
        ],
        &[PASSWORD],
    );

    assert!(!output.status.success());
    assert!(!stdout(&output).contains(SECRET_VALUE));
    assert!(!stderr(&output).contains(SECRET_VALUE));
}

#[test]
fn export_rejects_short_passphrase() {
    let env = TestEnv::new();
    let vault = env.path().join("short-pass-export.msv");
    let bundle = env.path().join("short-pass.msexp");
    init_vault(&env, &vault);
    let _ = add_item(&env, &vault, "short pass item");

    let output = run_cli(
        &env,
        [
            "export",
            "--output",
            path_str(&bundle),
            "--vault",
            path_str(&vault),
        ],
        &[PASSWORD, b"short"],
    );

    assert!(!output.status.success());
    assert_no_secret_leak(&output);
    assert!(!bundle.exists());
}

#[test]
fn wrong_password_returns_err() {
    let env = TestEnv::new();
    let vault = env.path().join("wrong-password.msv");
    init_vault(&env, &vault);
    let _ = add_item(&env, &vault, "wrong password item");

    let output = run_cli(
        &env,
        ["list", path_str(&vault)],
        &[b"wrong-password-never-real"],
    );

    assert!(!output.status.success());
    assert_no_secret_leak(&output);
}

#[test]
fn add_rejects_secret_flag() {
    let env = TestEnv::new();
    let vault = env.path().join("secret-flag-reject.msv");
    init_vault(&env, &vault);

    let output = run_cli(
        &env,
        [
            "add",
            "--label",
            "argv token",
            "--kind",
            "api-token",
            "--vault",
            path_str(&vault),
            "--secret",
            SECRET_VALUE,
        ],
        &[],
    );

    assert!(!output.status.success());
    assert_no_secret_leak(&output);
}

#[test]
fn export_stdout_has_no_secret_leak() {
    let env = TestEnv::new();
    let vault = env.path().join("export-no-leak.msv");
    let bundle = env.path().join("export-no-leak.msexp");
    init_vault(&env, &vault);
    let _ = add_item(&env, &vault, "export no leak item");

    let output = run_cli(
        &env,
        [
            "export",
            "--output",
            path_str(&bundle),
            "--vault",
            path_str(&vault),
        ],
        &[PASSWORD, EXPORT_PASS],
    );

    assert_success(&output);
    assert_no_secret_leak(&output);
    assert!(bundle.exists());
}

#[test]
fn list_label_with_newline_does_not_inject() {
    let env = TestEnv::new();
    let vault = env.path().join("newline-label.msv");
    init_vault(&env, &vault);
    let label = "primary label\nfake-id\tfake-label\tPassword";
    let add = run_cli(
        &env,
        [
            "add",
            "--label",
            label,
            "--kind",
            "secure-note",
            "--vault",
            path_str(&vault),
        ],
        &[PASSWORD, SECRET_VALUE.as_bytes()],
    );
    assert_success(&add);

    let list = run_cli(&env, ["list", path_str(&vault)], &[PASSWORD]);
    assert_success(&list);
    assert_no_secret_leak(&list);
    let stdout = stdout(&list);
    let rows: Vec<&str> = stdout.lines().collect();

    assert_eq!(rows.len(), 1, "list output must contain one row per item");
    let first_row = rows.first().expect("one rendered row");
    assert!(first_row.contains("primary label"));
    assert!(first_row.contains("\\n"));
    assert!(!stdout.contains("fake-id\tfake-label\tPassword"));
}

#[test]
fn help_documents_shell_history_risk_without_secret_values() {
    let env = TestEnv::new();
    let output = run_cli(&env, ["--help"], &[]);

    assert_success(&output);
    let help = stdout(&output);
    assert!(help.contains("shell-history leakage risk"));
    assert!(!help.contains(SECRET_VALUE));
    assert!(!help.contains("Master password:"));
    assert!(!help.contains("Secret value:"));
}

#[test]
fn add_rejects_plaintext_secret_argv() {
    let env = TestEnv::new();
    let vault = env.path().join("argv-reject.msv");
    init_vault(&env, &vault);

    let output = run_cli(
        &env,
        [
            "add",
            "--label",
            "argv token",
            "--kind",
            "api-token",
            "--vault",
            path_str(&vault),
            SECRET_VALUE,
        ],
        &[],
    );

    assert!(!output.status.success());
    assert_no_secret_leak(&output);
}

#[test]
fn import_rejects_tampered_bundle() {
    let env = TestEnv::new();
    let source = env.path().join("tamper-source.msv");
    let dest = env.path().join("tamper-dest.msv");
    let bundle = env.path().join("tampered.msexp");
    init_vault(&env, &source);
    init_vault(&env, &dest);
    let _ = add_item(&env, &source, "tamper import item");

    let export = run_cli(
        &env,
        [
            "export",
            "--output",
            path_str(&bundle),
            "--vault",
            path_str(&source),
        ],
        &[PASSWORD, EXPORT_PASS],
    );
    assert_success(&export);

    let mut bytes = std::fs::read(&bundle).expect("bundle bytes");
    assert!(bytes.len() > 64, "bundle must be long enough to tamper");
    *bytes.get_mut(64).expect("tamper offset") ^= 0x01;
    std::fs::write(&bundle, &bytes).expect("write tampered bundle");

    let import = run_cli(
        &env,
        [
            "import",
            "--input",
            path_str(&bundle),
            "--vault",
            path_str(&dest),
        ],
        &[PASSWORD, EXPORT_PASS],
    );
    assert!(!import.status.success());
    assert_no_secret_leak(&import);
    assert!(!stderr(&import).contains("panicked"));

    let list = run_cli(&env, ["list", path_str(&dest)], &[PASSWORD]);
    assert_success(&list);
    assert!(
        !stdout(&list).contains("tamper import item"),
        "failed import must leave destination vault unchanged"
    );
}

#[test]
fn init_rejects_mismatched_password_confirmation() {
    let env = TestEnv::new();
    let vault = env.path().join("mismatch.msv");
    let output = run_cli(
        &env,
        ["init", path_str(&vault)],
        &[PASSWORD, b"e2e-mismatch-password-never-real"],
    );

    assert!(!output.status.success());
    assert!(!vault.exists());
    assert_no_secret_leak(&output);
}

#[test]
fn init_refuses_existing_vault() {
    let env = TestEnv::new();
    let vault = env.path().join("existing-vault.msv");
    init_vault(&env, &vault);

    let second = run_cli(&env, ["init", path_str(&vault)], &[PASSWORD, PASSWORD]);
    assert!(!second.status.success());
    assert_no_secret_leak(&second);
}

#[test]
fn init_refuses_existing_output_path() {
    let env = TestEnv::new();
    let path = env.path().join("existing-output.msv");
    std::fs::write(&path, b"preexisting").expect("seed existing path");

    let output = run_cli(&env, ["init", path_str(&path)], &[PASSWORD, PASSWORD]);
    assert!(!output.status.success());
    assert_no_secret_leak(&output);
}

#[test]
fn export_refuses_existing_bundle() {
    let env = TestEnv::new();
    let vault = env.path().join("refuse-src.msv");
    let bundle = env.path().join("existing.msexp");
    init_vault(&env, &vault);
    let _ = add_item(&env, &vault, "overwrite candidate");

    let first = run_cli(
        &env,
        ["export", "--output", path_str(&bundle), "--vault", path_str(&vault)],
        &[PASSWORD, EXPORT_PASS],
    );
    assert_success(&first);
    let original_len = std::fs::metadata(&bundle).expect("first export metadata").len();

    let second = run_cli(
        &env,
        ["export", "--output", path_str(&bundle), "--vault", path_str(&vault)],
        &[PASSWORD, EXPORT_PASS],
    );
    let after_len = std::fs::metadata(&bundle).expect("second export metadata").len();
    if second.status.success() {
        assert!(after_len >= original_len, "atomic replace must not truncate bundle");
    } else {
        assert_eq!(after_len, original_len, "refused export must not modify existing bundle");
        assert_no_secret_leak(&second);
    }
}

#[test]
fn corrupted_vault_list_and_get_fail_without_plaintext_leak() {
    let env = TestEnv::new();
    let vault = env.path().join("corrupted.msv");
    init_vault(&env, &vault);
    let item_id = add_item(&env, &vault, "corrupt me");

    let mut bytes = std::fs::read(&vault).expect("vault bytes");
    let flip_at = bytes.len() / 2;
    assert!(flip_at > 26, "vault must have ciphertext region");
    *bytes.get_mut(flip_at).expect("ciphertext offset") ^= 0x01;
    std::fs::write(&vault, &bytes).expect("write corrupted vault");

    let list = run_cli(&env, ["list", path_str(&vault)], &[PASSWORD]);
    assert!(!list.status.success());
    assert_no_secret_leak(&list);
    assert!(!stderr(&list).contains("panicked"));

    let get = run_cli(
        &env,
        ["get", &item_id, "--vault", path_str(&vault)],
        &[PASSWORD],
    );
    assert!(!get.status.success());
    assert_no_secret_leak(&get);
    assert!(!stderr(&get).contains("panicked"));
}

#[test]
fn list_label_with_ansi_escape_does_not_inject_control_sequence() {
    let env = TestEnv::new();
    let vault = env.path().join("ansi-label.msv");
    init_vault(&env, &vault);
    let label = "primary\x1b[31mred";

    let add = run_cli(
        &env,
        [
            "add",
            "--label",
            label,
            "--kind",
            "secure-note",
            "--vault",
            path_str(&vault),
        ],
        &[PASSWORD, SECRET_VALUE.as_bytes()],
    );
    assert_success(&add);

    let list = run_cli(&env, ["list", path_str(&vault)], &[PASSWORD]);
    assert_success(&list);
    let rendered = stdout(&list);
    assert!(!rendered.contains('\u{001b}'));
    assert_eq!(rendered.lines().count(), 1);
}

#[test]
fn list_label_with_carriage_return_does_not_inject_control_sequence() {
    let env = TestEnv::new();
    let vault = env.path().join("cr-label.msv");
    init_vault(&env, &vault);
    let label = "primary\rfake-row";

    let add = run_cli(
        &env,
        [
            "add",
            "--label",
            label,
            "--kind",
            "secure-note",
            "--vault",
            path_str(&vault),
        ],
        &[PASSWORD, SECRET_VALUE.as_bytes()],
    );
    assert_success(&add);

    let list = run_cli(&env, ["list", path_str(&vault)], &[PASSWORD]);
    assert_success(&list);
    let rendered = stdout(&list);
    assert!(!rendered.contains('\r'));
    assert_eq!(rendered.lines().count(), 1);
}

fn init_vault(env: &TestEnv, path: &Path) {
    let output = run_cli(env, ["init", path_str(path)], &[PASSWORD, PASSWORD]);
    assert_success(&output);
}

fn add_item(env: &TestEnv, vault: &Path, label: &str) -> String {
    let output = run_cli(
        env,
        [
            "add",
            "--label",
            label,
            "--kind",
            "secure-note",
            "--vault",
            path_str(vault),
        ],
        &[PASSWORD, SECRET_VALUE.as_bytes()],
    );
    assert_success(&output);
    let rendered = stdout(&output);
    let id = first_output_line_with_prefix(&rendered, "Item ID: ").expect("item id line");
    assert!(
        is_opaque_item_id_hex32(id),
        "item id must be 32 hex characters"
    );
    id.to_string()
}

fn run_cli<const N: usize>(env: &TestEnv, args: [&str; N], stdin_lines: &[&[u8]]) -> Output {
    let _guard = run_cli_lock().lock().expect("run_cli mutex");
    assert!(
        std::env::var_os("MEISSNERSEAL_STDIN_PASSWORD").is_none(),
        "MEISSNERSEAL_STDIN_PASSWORD must not leak between tests"
    );
    // These are process-level E2E tests. Passwords are sent only through stdin;
    // production argv never receives secret values.
    // The public --stdin flag tells the binary to read prompts sequentially
    // from stdin instead of /dev/tty (unavailable in spawned subprocesses).
    let mut child = Command::new(env!("CARGO_BIN_EXE_meissnerseal"))
        .arg("--stdin")
        .args(args)
        .current_dir(env.path())
        .env_remove("MEISSNERSEAL_STDIN_PASSWORD")
        .env("HOME", env.path())
        .env("XDG_CONFIG_HOME", env.path().join(".config"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn meissnerseal");

    if let Some(mut stdin) = child.stdin.take() {
        for line in stdin_lines {
            use std::io::Write;
            stdin.write_all(line).expect("write test stdin");
            stdin.write_all(b"\n").expect("write test stdin newline");
        }
    }

    let started = Instant::now();
    loop {
        if let Some(_status) = child.try_wait().expect("poll meissnerseal") {
            return child.wait_with_output().expect("wait for meissnerseal");
        }
        if started.elapsed() >= CLI_TIMEOUT {
            let _ = child.kill();
            let output = child.wait_with_output().expect("collect timed out output");
            panic!(
                "command timed out after {:?}; stdout={} stderr={}",
                CLI_TIMEOUT,
                redact_output_stream(&output.stdout),
                redact_output_stream(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed with status {:?} (stdout/stderr redacted; run with -- --nocapture to inspect locally)",
        output.status.code(),
    );
}

fn assert_no_secret_leak(output: &Output) {
    for (label, secret) in [
        ("SECRET_VALUE", SECRET_VALUE.as_bytes()),
        ("PASSWORD",    PASSWORD),
        ("EXPORT_PASS", EXPORT_PASS),
    ] {
        assert!(
            !contains_subslice(&output.stdout, secret),
            "stdout leaked {label}"
        );
        assert!(
            !contains_subslice(&output.stderr, secret),
            "stderr leaked {label}"
        );
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("test path is UTF-8")
}

fn first_output_line_with_prefix<'a>(rendered: &'a str, prefix: &str) -> Option<&'a str> {
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(prefix).map(str::trim))
}

fn is_opaque_item_id_hex32(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn redact_output_stream(bytes: &[u8]) -> String {
    format!("[REDACTED:{} bytes]", bytes.len())
}

fn run_cli_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
