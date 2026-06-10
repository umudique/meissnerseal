use arcanum_core::{
    error::{CoreError, Result},
    item::{self, ItemKind, ItemSummary},
    vault::engine::{self as vault, CreateVaultParams, UnlockParams},
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
    /// Add a secret item (input via prompt or --stdin)
    Add,
    /// List item IDs and types (no secret values)
    List {
        /// Path to the .arcv vault file to open
        vault: PathBuf,
    },
    /// Retrieve a secret item (output via prompt, not stdout by default)
    Get,
    /// Export an encrypted .arcexp bundle
    Export,
    /// Import an encrypted .arcexp bundle
    Import,
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
        Commands::List { vault } => list_command(vault, stdout),
        Commands::Lock => {
            writeln!(stdout, "Vault is locked.")?;
            Ok(())
        }
        Commands::Add
        | Commands::Get
        | Commands::Export
        | Commands::Import
        | Commands::Transfer { .. }
        | Commands::Device { .. } => Err(CoreError::InvalidState(
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

fn list_command(vault_path: PathBuf, stdout: &mut dyn Write) -> Result<()> {
    let password = prompt_password("Master password: ")?;
    let output = list_vault(vault_path, password.into_bytes())?;
    write!(stdout, "{output}")?;
    Ok(())
}

fn list_vault(vault_path: PathBuf, password: Vec<u8>) -> Result<String> {
    let session = vault::unlock(UnlockParams {
        path: vault_path,
        password: SecretBytes::new(password),
    })?;
    let summaries = item::list(&session)?;
    Ok(render_item_summaries(&summaries))
}

fn prompt_password(prompt: &str) -> std::io::Result<String> {
    rpassword::prompt_password_stdout(prompt)
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
    use arcanum_core::item::{add, PlainItem};
    use clap::CommandFactory;
    use std::time::{SystemTime, UNIX_EPOCH};

    const KNOWN_SECRET: &str = "cli-list-secret-never-real";
    const PASSWORD: &[u8] = b"cli-test-password-never-real";

    #[test]
    fn init_and_list_help_contains_no_secret_value() {
        let help = help_text();

        assert!(help.contains("shell-history leakage risk"));
        assert!(!help.contains(KNOWN_SECRET));
        assert!(!help.contains("Master password:"));
        assert!(!help.contains("Confirm:"));
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
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn list_output_prints_label_and_kind_but_not_secret_field() {
        let path = unique_vault_path("cli-list-output");
        let create_result = vault::create(CreateVaultParams {
            path: path.clone(),
            password: SecretBytes::new(PASSWORD.to_vec()),
        });
        assert!(create_result.is_ok());

        let session = vault::unlock(UnlockParams {
            path: path.clone(),
            password: SecretBytes::new(PASSWORD.to_vec()),
        })
        .expect("test vault unlock succeeds");
        let add_result = add(
            &session,
            PlainItem {
                kind: ItemKind::ApiToken,
                label: "CI token".to_string(),
                secret: SecretBytes::new(KNOWN_SECRET.as_bytes().to_vec()),
                tags: Vec::new(),
            },
        );
        assert!(add_result.is_ok());
        drop(session);

        let output =
            list_vault(path.clone(), PASSWORD.to_vec()).expect("test list command succeeds");
        assert!(output.contains("CI token"));
        assert!(output.contains("ApiToken"));
        assert!(!output.contains(KNOWN_SECRET));

        let _ = std::fs::remove_file(path);
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
        std::env::temp_dir().join(format!("arcanum-{label}-{}-{now}.arcv", std::process::id()))
    }
}
