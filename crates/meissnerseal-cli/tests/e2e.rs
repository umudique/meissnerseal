// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::expect_used)]

use std::{
    path::Path,
    process::{Command, Output, Stdio},
};

use tempfile::TempDir;

const PASSWORD: &[u8] = b"e2e-test-password-never-real";
const EXPORT_PASS: &[u8] = b"e2e-export-passphrase-never-real";
const SECRET_VALUE: &str = "e2e-secret-value-never-real";

#[test]
fn init_creates_msv_vault_file() {
    let temp = TempDir::new().expect("tempdir");
    let vault = temp.path().join("init-ok.msv");

    let output = run_cli(["init", path_str(&vault)], &[PASSWORD, PASSWORD]);

    assert_success(&output);
    assert!(vault.exists());
    assert_eq!(vault.extension().and_then(|ext| ext.to_str()), Some("msv"));
}

#[test]
fn add_then_list_shows_item_without_secret() {
    let temp = TempDir::new().expect("tempdir");
    let vault = temp.path().join("add-list.msv");
    init_vault(&vault);

    let add = run_cli(
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

    let list = run_cli(["list", path_str(&vault)], &[PASSWORD]);
    assert_success(&list);
    let stdout = stdout(&list);
    assert!(stdout.contains("CI token"));
    assert!(stdout.contains("ApiToken"));
    assert!(!stdout.contains(SECRET_VALUE));
}

#[test]
fn add_then_get_uses_opaque_id_and_note_precedes_secret() {
    let temp = TempDir::new().expect("tempdir");
    let vault = temp.path().join("add-get.msv");
    init_vault(&vault);
    let item_id = add_item(&vault, "operator note");

    let output = run_cli(["get", &item_id, "--vault", path_str(&vault)], &[PASSWORD]);

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
    let temp = TempDir::new().expect("tempdir");
    let vault = temp.path().join("export-source.msv");
    let bundle = temp.path().join("exported.msexp");
    init_vault(&vault);
    let _ = add_item(&vault, "exported note");

    let output = run_cli(
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
    assert_eq!(
        bundle.extension().and_then(|ext| ext.to_str()),
        Some("msexp")
    );
    let metadata = std::fs::metadata(&bundle).expect("bundle metadata");
    assert!(metadata.len() > 0);
    let bytes = std::fs::read(&bundle).expect("bundle bytes");
    assert!(!contains_subslice(&bytes, SECRET_VALUE.as_bytes()));
}

#[test]
fn export_then_import_roundtrips_item() {
    let temp = TempDir::new().expect("tempdir");
    let source = temp.path().join("source.msv");
    let dest = temp.path().join("dest.msv");
    let bundle = temp.path().join("roundtrip.msexp");
    init_vault(&source);
    init_vault(&dest);
    let _ = add_item(&source, "roundtrip item");

    let export = run_cli(
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

    let list = run_cli(["list", path_str(&dest)], &[PASSWORD]);
    assert_success(&list);
    let stdout = stdout(&list);
    assert!(stdout.contains("roundtrip item"));
    assert!(!stdout.contains(SECRET_VALUE));
}

#[test]
fn lock_returns_ok() {
    let output = run_cli(["lock"], &[]);

    assert_success(&output);
    assert!(stdout(&output).contains("Vault is locked."));
}

#[test]
fn transfer_and_device_stubs_error_at_runtime() {
    let transfer = run_cli(["transfer", "create"], &[]);
    assert!(!transfer.status.success());
    assert!(stderr(&transfer).contains("command is not wired in MVP-0 CLI yet"));

    let device = run_cli(["device", "list"], &[]);
    assert!(!device.status.success());
    assert!(stderr(&device).contains("command is not wired in MVP-0 CLI yet"));
}

#[test]
fn get_with_wrong_item_id_returns_err() {
    let temp = TempDir::new().expect("tempdir");
    let vault = temp.path().join("wrong-id.msv");
    init_vault(&vault);
    let _ = add_item(&vault, "wrong id item");

    let output = run_cli(
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
fn help_documents_shell_history_risk_without_secret_values() {
    let output = run_cli(["--help"], &[]);

    assert_success(&output);
    let help = stdout(&output);
    assert!(help.contains("shell-history leakage risk"));
    assert!(!help.contains(SECRET_VALUE));
    assert!(!help.contains("Master password:"));
    assert!(!help.contains("Secret value:"));
}

#[test]
fn add_rejects_plaintext_secret_argv() {
    let temp = TempDir::new().expect("tempdir");
    let vault = temp.path().join("argv-reject.msv");
    init_vault(&vault);

    let output = run_cli(
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
}

fn init_vault(path: &Path) {
    let output = run_cli(["init", path_str(path)], &[PASSWORD, PASSWORD]);
    assert_success(&output);
}

fn add_item(vault: &Path, label: &str) -> String {
    let output = run_cli(
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
    let id = rendered
        .split_whitespace()
        .find(|word| word.len() == 32 && word.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .expect("opaque item id")
        .to_string();
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    id
}

fn run_cli<const N: usize>(args: [&str; N], stdin_lines: &[&[u8]]) -> Output {
    // These are process-level E2E tests. Passwords are sent only through stdin;
    // production argv never receives secret values.
    let mut child = Command::new(env!("CARGO_BIN_EXE_meissnerseal"))
        .args(args)
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

    child.wait_with_output().expect("wait for meissnerseal")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed: {}",
        stderr(output)
    );
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

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
