// SPDX-License-Identifier: Apache-2.0
use arcanum_core::{
    error::{CoreError, Result},
    item::{self, ItemKind, ItemSummary, PlainItem},
    vault::engine::{self as vault, CreateVaultParams, UnlockParams, VaultSession},
};
use arcanum_security::secret_lifecycle::SecretBytes;
use clap::{Parser, Subcommand};
use std::{io::Write, path::PathBuf};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "arcanum",
    about = "Local-first critical secrets vault with hybrid post-quantum-ready transfer",
    version,
    after_long_help = "Security: plaintext secrets must never be passed as command-line arguments. shell-history leakage risk: command-line arguments can leak through shell history and process listings. Use hidden prompts, --stdin, or file descriptors for secret input.",
    // Secrets must never be passed as command-line arguments.
    // Use --stdin, interactive prompt, or file descriptor input.
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault
    Init {
        /// Path to the .arcv vault file to create
        path: PathBuf,
    },
    /// Add a secret item (secret value via hidden prompt, never argv)
    Add {
        /// Non-secret display label for the item
        #[arg(long)]
        label: String,
        /// Item kind: password, seed-phrase, ssh-key, api-token, secure-note
        #[arg(long)]
        kind: String,
        /// Path to the .arcv vault file to open
        #[arg(long)]
        vault: PathBuf,
    },
    /// List item IDs and types (no secret values)
    List {
        /// Path to the .arcv vault file to open
        vault: PathBuf,
    },
    /// Retrieve a secret item (secret is printed to stdout after a NOTE line)
    Get {
        /// Opaque 32-character hex item id (from `arcanum list`)
        item_id: String,
        /// Path to the .arcv vault file to open
        #[arg(long)]
        vault: PathBuf,
    },
    /// Export an encrypted .arcexp bundle
    Export {
        /// Destination path for the encrypted .arcexp bundle
        #[arg(long)]
        output: PathBuf,
        /// Path to the .arcv vault file to open
        #[arg(long)]
        vault: PathBuf,
    },
    /// Import an encrypted .arcexp bundle
    Import {
        /// Source path of the encrypted .arcexp bundle
        #[arg(long)]
        input: PathBuf,
        /// Path to the .arcv vault file to open
        #[arg(long)]
        vault: PathBuf,
    },
    /// Lock the vault session
    Lock,
    /// Secure transfer operations
    Transfer {
        #[command(subcommand)]
        action: TransferCommands,
    },
    /// Device management
    Device {
        #[command(subcommand)]
        action: DeviceCommands,
    },
}

#[derive(Subcommand)]
enum TransferCommands {
    /// Create a transfer envelope
    Create,
    /// Receive a transfer envelope
    Receive,
}

#[derive(Subcommand)]
enum DeviceCommands {
    /// Pair with another device
    Pair,
    /// List approved devices
    List,
    /// Revoke a device
    Revoke,
}

fn main() {
    eprintln!("arcanum: alpha — do not store real secrets yet.");
    if let Err(error) = run(Cli::parse(), &mut std::io::stdout()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli, stdout: &mut dyn Write) -> Result<()> {
    match cli.command {
        Commands::Init { path } => init_vault(path, stdout),
        Commands::Add { label, kind, vault } => add_command(label, kind, vault, stdout),
        Commands::List { vault } => list_command(vault, stdout),
        Commands::Get { item_id, vault } => get_command(item_id, vault, stdout),
        Commands::Export { output, vault } => export_command(output, vault, stdout),
        Commands::Import { input, vault } => import_command(input, vault, stdout),
        Commands::Lock => {
            writeln!(stdout, "Vault is locked.")?;
            Ok(())
        }
        Commands::Transfer { .. } | Commands::Device { .. } => Err(CoreError::InvalidState(
            "command is not wired in MVP-0 CLI yet".into(),
        )),
    }
}

fn init_vault(path: PathBuf, stdout: &mut dyn Write) -> Result<()> {
    let mut password = prompt_password("Master password: ")?;
    let mut confirm = prompt_password("Confirm: ")?;

    if password != confirm {
        password.zeroize();
        confirm.zeroize();
        return Err(CoreError::InvalidState(
            "password confirmation mismatch".into(),
        ));
    }

    confirm.zeroize();
    let handle = vault::create(CreateVaultParams {
        path,
        password: SecretBytes::new(password.into_bytes()),
    })?;
    writeln!(stdout, "Created vault: {}", handle.path.display())?;
    Ok(())
}

fn add_command(label: String, kind: String, vault: PathBuf, stdout: &mut dyn Write) -> Result<()> {
    let kind = parse_item_kind(&kind)?;
    let password = prompt_password("Master password: ")?;
    let secret = prompt_password("Secret value: ")?;
    let item = PlainItem {
        kind,
        label,
        secret: SecretBytes::new(secret.into_bytes()),
        tags: Vec::new(),
    };
    add_item(vault, password.into_bytes(), item, stdout)
}

fn add_item(
    vault_path: PathBuf,
    password: Vec<u8>,
    item: PlainItem,
    stdout: &mut dyn Write,
) -> Result<()> {
    let session = unlock_session(vault_path, password)?;
    let id = item::add(&session, item)?;
    writeln!(stdout, "{}", hex_id(&id))?;
    Ok(())
}

fn get_command(item_id: String, vault: PathBuf, stdout: &mut dyn Write) -> Result<()> {
    let id = hex_decode_id(&item_id)?;
    let password = prompt_password("Master password: ")?;
    get_item(vault, password.into_bytes(), id, stdout)
}

fn get_item(
    vault_path: PathBuf,
    password: Vec<u8>,
    id: [u8; 16],
    stdout: &mut dyn Write,
) -> Result<()> {
    let session = unlock_session(vault_path, password)?;
    item::with_item(&session, id, |view| {
        // The NOTE line must precede the secret so the operator is warned that
        // plaintext is about to land on stdout (CONTRACT A-02 / G-02).
        writeln!(stdout, "NOTE: secret printed to stdout")?;
        view.secret.with_secret(|secret| {
            writeln!(stdout, "{}", String::from_utf8_lossy(secret))?;
            Ok(())
        })
    })
}

fn export_command(output: PathBuf, vault: PathBuf, stdout: &mut dyn Write) -> Result<()> {
    let password = prompt_password("Master password: ")?;
    let passphrase = prompt_password("Export passphrase: ")?;
    export_bundle(
        vault,
        password.into_bytes(),
        passphrase.into_bytes(),
        output,
        stdout,
    )
}

fn export_bundle(
    vault_path: PathBuf,
    password: Vec<u8>,
    passphrase: Vec<u8>,
    output: PathBuf,
    stdout: &mut dyn Write,
) -> Result<()> {
    let session = unlock_session(vault_path, password)?;
    let mut passphrase = passphrase;
    let bundle = arcanum_core::export::export(&session, &passphrase);
    passphrase.zeroize();
    let bundle = bundle?;
    // Write raw bundle bytes to disk only; never log or print the bytes (G-03).
    std::fs::write(&output, &bundle)?;
    writeln!(stdout, "Exported encrypted bundle to {}", output.display())?;
    Ok(())
}

fn import_command(input: PathBuf, vault: PathBuf, stdout: &mut dyn Write) -> Result<()> {
    let password = prompt_password("Master password: ")?;
    let passphrase = prompt_password("Import passphrase: ")?;
    import_bundle(
        vault,
        password.into_bytes(),
        passphrase.into_bytes(),
        input,
        stdout,
    )
}

fn import_bundle(
    vault_path: PathBuf,
    password: Vec<u8>,
    passphrase: Vec<u8>,
    input: PathBuf,
    stdout: &mut dyn Write,
) -> Result<()> {
    let session = unlock_session(vault_path, password)?;
    let bytes = std::fs::read(&input)?;
    let mut passphrase = passphrase;
    let ids = arcanum_core::export::import(&session, &bytes, &passphrase);
    passphrase.zeroize();
    // Print imported item IDs only — never item secrets.
    for id in &ids? {
        writeln!(stdout, "{}", hex_id(id))?;
    }
    Ok(())
}

fn list_command(vault_path: PathBuf, stdout: &mut dyn Write) -> Result<()> {
    let password = prompt_password("Master password: ")?;
    let output = list_vault(vault_path, password.into_bytes())?;
    write!(stdout, "{output}")?;
    Ok(())
}

fn list_vault(vault_path: PathBuf, password: Vec<u8>) -> Result<String> {
    let session = unlock_session(vault_path, password)?;
    let summaries = item::list(&session)?;
    Ok(render_item_summaries(&summaries))
}

fn unlock_session(vault_path: PathBuf, password: Vec<u8>) -> Result<VaultSession> {
    vault::unlock(UnlockParams {
        path: vault_path,
        password: SecretBytes::new(password),
    })
}

fn prompt_password(prompt: &str) -> std::io::Result<String> {
    rpassword::prompt_password_stdout(prompt)
}

fn parse_item_kind(kind: &str) -> Result<ItemKind> {
    match kind {
        "password" => Ok(ItemKind::Password),
        "seed-phrase" => Ok(ItemKind::SeedPhrase),
        "ssh-key" => Ok(ItemKind::SshPrivateKey),
        "api-token" => Ok(ItemKind::ApiToken),
        "secure-note" => Ok(ItemKind::SecureNote),
        other => Err(CoreError::InvalidState(format!(
            "unknown item kind: {other} (expected password|seed-phrase|ssh-key|api-token|secure-note)"
        ))),
    }
}

fn hex_decode_id(s: &str) -> Result<[u8; 16]> {
    if s.len() != 32 {
        return Err(CoreError::InvalidState(
            "item id must be 32 hexadecimal characters".into(),
        ));
    }
    let mut id = [0u8; 16];
    for (i, slot) in id.iter_mut().enumerate() {
        let start = i
            .checked_mul(2)
            .ok_or_else(|| CoreError::InvalidState("item id offset overflow".into()))?;
        let end = start
            .checked_add(2)
            .ok_or_else(|| CoreError::InvalidState("item id offset overflow".into()))?;
        let pair = s
            .get(start..end)
            .ok_or_else(|| CoreError::InvalidState("item id truncated".into()))?;
        *slot = u8::from_str_radix(pair, 16)
            .map_err(|_| CoreError::InvalidState("item id contains non-hex characters".into()))?;
    }
    Ok(id)
}

fn render_item_summaries(summaries: &[ItemSummary]) -> String {
    let mut out = String::new();
    for summary in summaries {
        out.push_str(&hex_id(&summary.id));
        out.push('\t');
        out.push_str(&summary.label);
        out.push('\t');
        out.push_str(item_kind_name(&summary.kind));
        out.push('\n');
    }
    out
}

fn item_kind_name(kind: &ItemKind) -> &'static str {
    match kind {
        ItemKind::Password => "Password",
        ItemKind::SeedPhrase => "SeedPhrase",
        ItemKind::SshPrivateKey => "SshPrivateKey",
        ItemKind::ApiToken => "ApiToken",
        ItemKind::SecureNote => "SecureNote",
    }
}

fn hex_id(id: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in id {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    const KNOWN_SECRET: &str = "cli-list-secret-never-real";
    const PASSWORD: &[u8] = b"cli-test-password-never-real";
    const EXPORT_PASSPHRASE: &[u8] = b"cli-export-passphrase-never-real";

    #[test]
    fn init_and_list_help_contains_no_secret_value() {
        let help = help_text();

        assert!(help.contains("shell-history leakage risk"));
        assert!(!help.contains(KNOWN_SECRET));
        assert!(!help.contains("Master password:"));
        assert!(!help.contains("Confirm:"));
        assert!(!help.contains("Secret value:"));
    }

    #[test]
    fn plaintext_password_argv_is_rejected() {
        let result = Cli::try_parse_from([
            "arcanum",
            "init",
            "/tmp/test-vault.arcv",
            "plaintext-password-never-real",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn add_does_not_accept_secret_value_through_argv() {
        // `add` exposes only --label/--kind/--vault; a positional secret value
        // (or a --secret flag) must be rejected at parse time (G-01).
        let positional = Cli::try_parse_from([
            "arcanum",
            "add",
            "--label",
            "token",
            "--kind",
            "api-token",
            "--vault",
            "/tmp/test-vault.arcv",
            "plaintext-secret-never-real",
        ]);
        assert!(positional.is_err());

        let flagged = Cli::try_parse_from([
            "arcanum",
            "add",
            "--label",
            "token",
            "--kind",
            "api-token",
            "--vault",
            "/tmp/test-vault.arcv",
            "--secret",
            "plaintext-secret-never-real",
        ]);
        assert!(flagged.is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn add_then_list_shows_label_and_kind_but_not_secret() {
        let path = unique_vault_path("cli-add-list");
        create_test_vault(&path);

        let mut sink = Vec::new();
        add_item(
            path.clone(),
            PASSWORD.to_vec(),
            PlainItem {
                kind: ItemKind::ApiToken,
                label: "CI token".to_string(),
                secret: SecretBytes::new(KNOWN_SECRET.as_bytes().to_vec()),
                tags: Vec::new(),
            },
            &mut sink,
        )
        .expect("CLI add path succeeds");

        let listing = list_vault(path.clone(), PASSWORD.to_vec()).expect("CLI list path succeeds");
        assert!(listing.contains("CI token"));
        assert!(listing.contains("ApiToken"));
        assert!(!listing.contains(KNOWN_SECRET));
        // The add path prints only the opaque item id, never the secret.
        assert!(!String::from_utf8_lossy(&sink).contains(KNOWN_SECRET));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn get_prints_note_line_before_secret() {
        let path = unique_vault_path("cli-get-note");
        create_test_vault(&path);
        let id = add_known_item(&path, "vault key", KNOWN_SECRET);

        let mut sink = Vec::new();
        get_item(path.clone(), PASSWORD.to_vec(), id, &mut sink).expect("CLI get path succeeds");
        let output = String::from_utf8(sink).expect("get output is UTF-8");

        let note_index = output
            .find("NOTE: secret printed to stdout")
            .expect("get output must carry the NOTE warning");
        let secret_index = output
            .find(KNOWN_SECRET)
            .expect("get output must contain the requested secret");
        assert!(
            note_index < secret_index,
            "NOTE warning must precede the secret payload"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn export_writes_nonempty_bundle_without_leaking_secret() {
        let path = unique_vault_path("cli-export");
        create_test_vault(&path);
        let _ = add_known_item(&path, "exported note", KNOWN_SECRET);
        let bundle_path = unique_vault_path("cli-export-bundle");

        let mut sink = Vec::new();
        export_bundle(
            path.clone(),
            PASSWORD.to_vec(),
            EXPORT_PASSPHRASE.to_vec(),
            bundle_path.clone(),
            &mut sink,
        )
        .expect("CLI export path succeeds");

        let written = std::fs::read(&bundle_path).expect("export bundle file exists");
        assert!(!written.is_empty(), "export must write a non-empty bundle");
        // The encrypted bundle must not contain the plaintext secret bytes.
        assert!(!contains_subslice(&written, KNOWN_SECRET.as_bytes()));
        // The confirmation line never echoes the bundle bytes or the secret.
        assert!(!String::from_utf8_lossy(&sink).contains(KNOWN_SECRET));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(bundle_path);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn export_then_import_roundtrips_item_ids_only() {
        let path = unique_vault_path("cli-import");
        create_test_vault(&path);
        let _ = add_known_item(&path, "roundtrip note", KNOWN_SECRET);
        let bundle_path = unique_vault_path("cli-import-bundle");

        export_bundle(
            path.clone(),
            PASSWORD.to_vec(),
            EXPORT_PASSPHRASE.to_vec(),
            bundle_path.clone(),
            &mut Vec::new(),
        )
        .expect("export for import roundtrip succeeds");

        let mut sink = Vec::new();
        import_bundle(
            path.clone(),
            PASSWORD.to_vec(),
            EXPORT_PASSPHRASE.to_vec(),
            bundle_path.clone(),
            &mut sink,
        )
        .expect("CLI import path succeeds");
        let printed = String::from_utf8(sink).expect("import output is UTF-8");

        // Import prints item ids (32 hex chars), never the secret.
        assert!(!printed.contains(KNOWN_SECRET));
        assert!(printed
            .trim()
            .lines()
            .all(|line| line.len() == 32 && line.bytes().all(|b| b.is_ascii_hexdigit())));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(bundle_path);
    }

    #[test]
    fn hex_decode_id_rejects_malformed_input() {
        assert!(hex_decode_id("too-short").is_err());
        assert!(hex_decode_id(&"z".repeat(32)).is_err());
        assert!(hex_decode_id(&"0".repeat(33)).is_err());
        assert!(hex_decode_id(&"ab".repeat(16)).is_ok());
    }

    #[test]
    fn parse_item_kind_rejects_unknown() {
        assert!(parse_item_kind("password").is_ok());
        assert!(parse_item_kind("secure-note").is_ok());
        assert!(parse_item_kind("not-a-kind").is_err());
    }

    fn create_test_vault(path: &Path) {
        vault::create(CreateVaultParams {
            path: path.to_path_buf(),
            password: SecretBytes::new(PASSWORD.to_vec()),
        })
        .expect("test vault creation succeeds");
    }

    fn add_known_item(path: &Path, label: &str, secret: &str) -> [u8; 16] {
        let session =
            unlock_session(path.to_path_buf(), PASSWORD.to_vec()).expect("unlock test vault");
        item::add(
            &session,
            PlainItem {
                kind: ItemKind::SecureNote,
                label: label.to_string(),
                secret: SecretBytes::new(secret.as_bytes().to_vec()),
                tags: Vec::new(),
            },
        )
        .expect("seed item add succeeds")
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn help_text() -> String {
        let mut bytes = Vec::new();
        Cli::command()
            .write_long_help(&mut bytes)
            .expect("help generation succeeds");
        String::from_utf8(bytes).expect("help is valid UTF-8")
    }

    fn unique_vault_path(label: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after unix epoch")
            .as_nanos();
        std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
            .join(format!("arcanum-{label}-{}-{now}.arcv", std::process::id()))
    }
}
