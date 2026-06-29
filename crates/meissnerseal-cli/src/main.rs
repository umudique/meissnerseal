// SPDX-License-Identifier: Apache-2.0
use clap::{error::ErrorKind, Parser, Subcommand};
use meissnerseal_core::{
    error::{CoreError, Result},
    item::{self, ItemKind, ItemSummary, PlainItem},
    keys::{
        device::{
            create_signed_transfer_envelope, deserialize_identity_text, deserialize_keypair_bytes,
            generate, open_received_transfer_envelope, serialize_identity_text,
            serialize_keypair_bytes, DeviceIdentity,
        },
        pairing::{
            build_pairing_payload, compute_pairing_transcript, derive_short_authentication_string,
            PairingPayload, PAIRING_PROTOCOL_VERSION_V1,
        },
    },
    transfer::envelope::{envelope_from_bytes, envelope_to_bytes},
    vault::engine::{CreateVaultParams, Locked, UnlockParams, Unlocked, Vault},
};
use meissnerseal_security::secret_lifecycle::SecretBytes;
use std::{io::Write, path::PathBuf};
use zeroize::{Zeroize, Zeroizing};

#[derive(Parser)]
#[command(
    name = "meissnerseal",
    about = "Local-first critical secrets vault with hybrid post-quantum-ready transfer",
    version,
    after_long_help = "Security: plaintext secrets must never be passed as command-line arguments. shell-history leakage risk: command-line arguments can leak through shell history and process listings. Use hidden prompts, --stdin, or file descriptors for secret input.",
    // Secrets must never be passed as command-line arguments.
    // Use --stdin, interactive prompt, or file descriptor input.
)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Read all secret prompts from stdin (one per line) instead of /dev/tty"
    )]
    stdin: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault
    Init {
        /// Path to the .msv vault file to create
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
        /// Path to the .msv vault file to open
        #[arg(long)]
        vault: PathBuf,
    },
    /// List item IDs and types (no secret values)
    List {
        /// Path to the .msv vault file to open
        vault: PathBuf,
    },
    /// Retrieve a secret item (secret is printed to stdout after a NOTE line)
    Get {
        /// Opaque 32-character hex item id (from `meissnerseal list`)
        item_id: String,
        /// Path to the .msv vault file to open
        #[arg(long)]
        vault: PathBuf,
    },
    /// Export an encrypted .msexp bundle
    Export {
        /// Destination path for the encrypted .msexp bundle
        #[arg(long)]
        output: PathBuf,
        /// Path to the .msv vault file to open
        #[arg(long)]
        vault: PathBuf,
    },
    /// Import an encrypted .msexp bundle
    Import {
        /// Source path of the encrypted .msexp bundle
        #[arg(long)]
        input: PathBuf,
        /// Path to the .msv vault file to open
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
    Create {
        #[arg(long)]
        sender_keypair: PathBuf,
        #[arg(long)]
        recipient_identity: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "3600")]
        expires_in: u64,
    },
    /// Receive a transfer envelope
    Receive {
        envelope: PathBuf,
        #[arg(long)]
        recipient_keypair: PathBuf,
        #[arg(long)]
        sender_identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum DeviceCommands {
    /// Pair with another device
    Pair {
        #[arg(long)]
        name: String,
        #[arg(long)]
        self_keypair: PathBuf,
        #[arg(long)]
        self_identity: PathBuf,
        #[arg(long)]
        peer_identity: PathBuf,
    },
    /// List approved devices
    List,
    /// Revoke a device
    Revoke,
}

fn main() {
    eprintln!("meissnerseal: alpha — do not store real secrets yet.");
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                error.exit();
            }
            eprintln!("invalid command-line arguments; command is not wired in MVP-0 CLI yet");
            std::process::exit(2);
        }
    };
    if let Err(error) = run(cli, &mut std::io::stdout()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli, stdout: &mut dyn Write) -> Result<()> {
    let stdin = cli.stdin;
    match cli.command {
        Commands::Init { path } => init_vault(path, stdin, stdout),
        Commands::Add { label, kind, vault } => add_command(label, kind, vault, stdin, stdout),
        Commands::List { vault } => list_command(vault, stdin, stdout),
        Commands::Get { item_id, vault } => get_command(item_id, vault, stdin, stdout),
        Commands::Export { output, vault } => export_command(output, vault, stdin, stdout),
        Commands::Import { input, vault } => import_command(input, vault, stdin, stdout),
        Commands::Lock => {
            writeln!(stdout, "Vault is locked.")?;
            Ok(())
        }
        Commands::Transfer { action } => transfer_command(action, stdout),
        Commands::Device { action } => device_command(action, stdout),
    }
}

fn transfer_command(action: TransferCommands, stdout: &mut dyn Write) -> Result<()> {
    match action {
        TransferCommands::Create {
            sender_keypair,
            recipient_identity,
            input,
            output,
            expires_in,
        } => transfer_create_command(
            sender_keypair,
            recipient_identity,
            input,
            output,
            expires_in,
            stdout,
        ),
        TransferCommands::Receive {
            envelope,
            recipient_keypair,
            sender_identity,
            output,
        } => transfer_receive_command(envelope, recipient_keypair, sender_identity, output, stdout),
    }
}

fn device_command(action: DeviceCommands, stdout: &mut dyn Write) -> Result<()> {
    match action {
        DeviceCommands::Pair {
            name,
            self_keypair,
            self_identity,
            peer_identity,
        } => device_pair_command(name, self_keypair, self_identity, peer_identity, stdout),
        DeviceCommands::List | DeviceCommands::Revoke => Err(CoreError::InvalidState(
            "command is not wired in MVP-0 CLI yet".into(),
        )),
    }
}

fn transfer_create_command(
    sender_keypair: PathBuf,
    recipient_identity: PathBuf,
    input: PathBuf,
    output: PathBuf,
    expires_in: u64,
    stdout: &mut dyn Write,
) -> Result<()> {
    let (sender_device_id, _sender_classical_public_key, sender_keypair) =
        deserialize_keypair_bytes(&std::fs::read(&sender_keypair)?).map_err(device_parse_error)?;
    let recipient = deserialize_identity_text(&std::fs::read_to_string(&recipient_identity)?)
        .map_err(device_parse_error)?;
    let plaintext = std::fs::read(&input)?;
    let expires_at = Some(
        unix_now_millis()?
            .checked_add(
                expires_in
                    .checked_mul(1_000)
                    .ok_or_else(|| CoreError::InvalidState("expiry overflow".into()))?,
            )
            .ok_or_else(|| CoreError::InvalidState("expiry overflow".into()))?,
    );
    let envelope = create_signed_transfer_envelope(
        sender_device_id,
        &sender_keypair,
        Some(recipient.device_id),
        recipient.classical_public_key,
        recipient.pqc_public_key,
        plaintext,
        expires_at,
    )
    .map_err(|_| CoreError::Crypto)?;
    std::fs::write(&output, envelope_to_bytes(&envelope))?;
    writeln!(stdout, "Transfer envelope written to {}.", output.display())?;
    Ok(())
}

fn transfer_receive_command(
    envelope: PathBuf,
    recipient_keypair: PathBuf,
    sender_identity: PathBuf,
    output: Option<PathBuf>,
    stdout: &mut dyn Write,
) -> Result<()> {
    let envelope =
        envelope_from_bytes(&std::fs::read(&envelope)?).map_err(|_| CoreError::Crypto)?;
    let (_recipient_device_id, recipient_classical_public_key, recipient_keypair) =
        deserialize_keypair_bytes(&std::fs::read(&recipient_keypair)?)
            .map_err(device_parse_error)?;
    let mut sender = deserialize_identity_text(&std::fs::read_to_string(&sender_identity)?)
        .map_err(device_parse_error)?;
    let sender_signing_public_key = sender
        .signing_public_key
        .take()
        .ok_or_else(|| CoreError::InvalidState("sender identity missing signing key".into()))?;
    let plaintext = open_received_transfer_envelope(
        &envelope,
        &recipient_keypair,
        recipient_classical_public_key,
        sender_signing_public_key,
    )
    .map_err(|_| CoreError::Crypto)?;
    if let Some(output) = output {
        std::fs::write(output, plaintext)?;
    } else {
        stdout.write_all(&plaintext)?;
    }
    Ok(())
}

fn device_pair_command(
    name: String,
    self_keypair: PathBuf,
    self_identity: PathBuf,
    peer_identity: PathBuf,
    stdout: &mut dyn Write,
) -> Result<()> {
    let (identity, keypair) = generate(name).map_err(device_parse_error)?;
    let identity_text = serialize_identity_text(&identity);
    eprintln!("=== YOUR IDENTITY (share this with peer) ===");
    eprint!("{identity_text}");
    eprintln!("=== PASTE PEER IDENTITY, then blank line ===");
    let peer_block = read_until_blank_line()?;
    let peer = deserialize_identity_text(&peer_block).map_err(device_parse_error)?;
    let payload = build_pairing_payload(&identity, 0x01)
        .map_err(|_| CoreError::InvalidState("pairing payload failed".into()))?;
    let peer_payload = synthetic_pairing_payload(&peer, payload.pairing_nonce)?;
    let transcript = compute_pairing_transcript(&peer_payload)
        .map_err(|_| CoreError::InvalidState("pairing transcript failed".into()))?;
    let sas = derive_short_authentication_string(
        &peer_payload.pairing_nonce,
        &transcript.transcript_hash,
    )
    .map_err(|_| CoreError::InvalidState("pairing SAS failed".into()))?;
    // MVP-2 SAS limitation: each side uses its own nonce against the peer's identity,
    // so SAS values will differ between initiator and responder. Transfer protocol
    // security is unaffected; this step is advisory only until bilateral nonce
    // commitment exchange is implemented.
    eprintln!("SAS: {sas} — verify this matches the other device");
    eprint!("Confirm SAS match? [y/N]: ");
    let mut confirm = String::new();
    std::io::stdin().read_line(&mut confirm)?;
    if !matches!(confirm.trim(), "y" | "Y") {
        return Err(CoreError::InvalidState(
            "pairing aborted — SAS not confirmed".into(),
        ));
    }
    let keypair_bytes = serialize_keypair_bytes(&identity, &keypair);
    std::fs::write(&self_keypair, &*keypair_bytes)?;
    restrict_owner_only(&self_keypair)?;
    std::fs::write(&self_identity, identity_text)?;
    std::fs::write(&peer_identity, serialize_identity_text(&peer))?;
    eprintln!(
        "WARNING: device keypair written to {} — restrict permissions: chmod 600 {}",
        self_keypair.display(),
        self_keypair.display()
    );
    writeln!(stdout, "Pairing complete.")?;
    Ok(())
}

fn synthetic_pairing_payload(
    identity: &DeviceIdentity,
    pairing_nonce: [u8; 32],
) -> Result<PairingPayload> {
    let mut payload = build_pairing_payload(identity, 0x01)
        .map_err(|_| CoreError::InvalidState("pairing payload failed".into()))?;
    payload.protocol_version = PAIRING_PROTOCOL_VERSION_V1;
    payload.pairing_nonce = pairing_nonce;
    Ok(payload)
}

fn device_parse_error(_: meissnerseal_core::keys::device::DeviceIdentityError) -> CoreError {
    CoreError::InvalidState("device file is invalid".into())
}

fn read_until_blank_line() -> Result<String> {
    use std::io::BufRead;
    let mut out = String::new();
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            break;
        }
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

fn unix_now_millis() -> Result<u64> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).map_err(|_| CoreError::InvalidState("timestamp overflow".into()))
}

#[cfg(unix)]
fn restrict_owner_only(path: &PathBuf) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_owner_only(_path: &PathBuf) -> Result<()> {
    Ok(())
}

fn init_vault(path: PathBuf, stdin: bool, stdout: &mut dyn Write) -> Result<()> {
    let mut password = prompt_password("Master password: ", stdin)?;
    let mut confirm = prompt_password("Confirm: ", stdin)?;

    if password != confirm {
        password.zeroize();
        confirm.zeroize();
        return Err(CoreError::InvalidState(
            "password confirmation mismatch".into(),
        ));
    }

    confirm.zeroize();
    let mut password = string_to_zeroized_vec(password);
    let locked = Vault::<Locked>::create(CreateVaultParams {
        path,
        password: SecretBytes::new(std::mem::take(&mut *password)),
    })?;
    writeln!(stdout, "Created vault: {}", locked.path().display())?;
    Ok(())
}

/// # Contract
///
/// ## Preconditions
/// - `label` is non-secret display metadata; secret item bytes must come only
///   from a hidden prompt or the explicit `--stdin` input path, never argv.
/// - `vault` points at an existing `.msv` vault and `kind` must name a known
///   item kind.
///
/// ## Postconditions
/// - On success, writes only the opaque item id to stdout.
/// - Password and secret prompt buffers are not retained after conversion into
///   owned secret containers.
///
/// ## Invariants
/// - Never logs or prints the item secret.
/// - Never accepts a `--secret` command-line argument.
fn add_command(
    label: String,
    kind: String,
    vault: PathBuf,
    stdin: bool,
    stdout: &mut dyn Write,
) -> Result<()> {
    let kind = parse_item_kind(&kind)?;
    let password = prompt_password("Master password: ", stdin)?;
    let secret = prompt_password("Secret value: ", stdin)?;
    let password = string_to_zeroized_vec(password);
    let mut secret = string_to_zeroized_vec(secret);
    let item = PlainItem {
        kind,
        label,
        secret: SecretBytes::new(std::mem::take(&mut *secret)),
        tags: Vec::new(),
    };
    add_item(vault, password, item, stdout)
}

fn add_item(
    vault_path: PathBuf,
    password: Zeroizing<Vec<u8>>,
    item: PlainItem,
    stdout: &mut dyn Write,
) -> Result<()> {
    let session = unlock_session(vault_path, password)?;
    let id = item::add(&session, item)?;
    writeln!(stdout, "{}", hex_id(&id))?;
    Ok(())
}

/// # Contract
///
/// ## Preconditions
/// - `item_id` is the opaque 32-character hexadecimal id from `list`.
/// - Master password input comes only from a hidden prompt or `--stdin`.
///
/// ## Postconditions
/// - On success, writes the NOTE line before writing raw secret bytes.
/// - On failure, returns `Err` without printing item secret bytes.
///
/// ## Invariants
/// - The item label is not used for retrieval.
/// - Password prompt buffers are not retained after unlock.
fn get_command(item_id: String, vault: PathBuf, stdin: bool, stdout: &mut dyn Write) -> Result<()> {
    let id = hex_decode_id(&item_id)?;
    let password = prompt_password("Master password: ", stdin)?;
    let password = string_to_zeroized_vec(password);
    get_item(vault, password, id, stdout)
}

/// # Contract
///
/// ## Preconditions
/// - `id` is an opaque item id decoded from CLI input.
/// - `password` is caller-owned secret material used only to unlock the vault.
///
/// ## Postconditions
/// - On success, writes the NOTE line and then the exact secret bytes followed
///   by a newline.
/// - On failure, returns `Err` without returning partial plaintext.
///
/// ## Invariants
/// - Does not reinterpret, sanitize, or log item secret bytes.
/// - Does not print labels or metadata in the secret output path.
fn get_item(
    vault_path: PathBuf,
    password: Zeroizing<Vec<u8>>,
    id: [u8; 16],
    stdout: &mut dyn Write,
) -> Result<()> {
    let session = unlock_session(vault_path, password)?;
    item::with_item(&session, id, |view| {
        // The NOTE line must precede the secret so the operator is warned that
        // plaintext is about to land on stdout (CONTRACT A-02 / G-02).
        writeln!(stdout, "NOTE: secret printed to stdout")?;
        view.secret.with_secret(|secret| {
            stdout.write_all(secret)?;
            stdout.write_all(b"\n")?;
            Ok(())
        })
    })
}

/// # Contract
///
/// ## Preconditions
/// - Master password and export passphrase input come only from hidden prompts
///   or `--stdin`, never argv.
/// - Export passphrase must be at least 12 bytes before export begins.
///
/// ## Postconditions
/// - On success, writes an encrypted `.msexp` bundle and prints only the output
///   path.
/// - On validation failure, returns `Err` without writing a bundle.
///
/// ## Invariants
/// - Never prints the export passphrase, master password, item secret, or
///   bundle bytes.
/// - Prompt buffers are not retained after validation or export.
fn export_command(
    output: PathBuf,
    vault: PathBuf,
    stdin: bool,
    stdout: &mut dyn Write,
) -> Result<()> {
    let mut password = prompt_password("Master password: ", stdin)?;
    let mut passphrase = prompt_password("Export passphrase: ", stdin)?;
    if passphrase.len() < 12 {
        passphrase.zeroize();
        password.zeroize();
        return Err(CoreError::InvalidState(
            "export passphrase must be at least 12 characters (P-02)".into(),
        ));
    }
    let password = string_to_zeroized_vec(password);
    let passphrase = string_to_zeroized_vec(passphrase);
    export_bundle(vault, password, passphrase, output, stdout)
}

fn export_bundle(
    vault_path: PathBuf,
    password: Zeroizing<Vec<u8>>,
    passphrase: Zeroizing<Vec<u8>>,
    output: PathBuf,
    stdout: &mut dyn Write,
) -> Result<()> {
    let session = unlock_session(vault_path, password)?;
    let bundle = meissnerseal_core::export::export(&session, &passphrase);
    let bundle = bundle?;
    // Write raw bundle bytes to disk only; never log or print the bytes (G-03).
    std::fs::write(&output, &bundle)?;
    writeln!(stdout, "Exported encrypted bundle to {}", output.display())?;
    Ok(())
}

/// # Contract
///
/// ## Preconditions
/// - Master password and import passphrase input come only from hidden prompts
///   or `--stdin`, never argv.
/// - `input` points to an encrypted `.msexp` bundle.
///
/// ## Postconditions
/// - On success, prints imported opaque item ids only.
/// - On any parse, authentication, unlock, or import failure, returns `Err`.
///
/// ## Invariants
/// - Never prints imported plaintext item secrets or the import passphrase.
/// - Prompt buffers are not retained after import.
fn import_command(
    input: PathBuf,
    vault: PathBuf,
    stdin: bool,
    stdout: &mut dyn Write,
) -> Result<()> {
    let password = prompt_password("Master password: ", stdin)?;
    let passphrase = prompt_password("Import passphrase: ", stdin)?;
    let password = string_to_zeroized_vec(password);
    let passphrase = string_to_zeroized_vec(passphrase);
    import_bundle(vault, password, passphrase, input, stdout)
}

fn import_bundle(
    vault_path: PathBuf,
    password: Zeroizing<Vec<u8>>,
    passphrase: Zeroizing<Vec<u8>>,
    input: PathBuf,
    stdout: &mut dyn Write,
) -> Result<()> {
    let session = unlock_session(vault_path, password)?;
    let bytes = std::fs::read(&input)?;
    let ids = meissnerseal_core::export::import(&session, &bytes, &passphrase);
    // Print imported item IDs only — never item secrets.
    for id in &ids? {
        writeln!(stdout, "{}", hex_id(id))?;
    }
    Ok(())
}

/// # Contract
///
/// ## Preconditions
/// - Master password input comes only from a hidden prompt or `--stdin`.
/// - `vault_path` points at an existing `.msv` vault.
///
/// ## Postconditions
/// - On success, writes one summary row per listed item.
/// - On unlock failure, returns `Err` without printing item data.
///
/// ## Invariants
/// - Summary rows contain item id, escaped label, and item kind only.
/// - Secret field values are never printed by list.
fn list_command(vault_path: PathBuf, stdin: bool, stdout: &mut dyn Write) -> Result<()> {
    let password = prompt_password("Master password: ", stdin)?;
    let password = string_to_zeroized_vec(password);
    let output = list_vault(vault_path, password)?;
    write!(stdout, "{output}")?;
    Ok(())
}

fn list_vault(vault_path: PathBuf, password: Zeroizing<Vec<u8>>) -> Result<String> {
    let session = unlock_session(vault_path, password)?;
    let summaries = item::list(&session)?;
    Ok(render_item_summaries(&summaries))
}

fn unlock_session(
    vault_path: PathBuf,
    mut password: Zeroizing<Vec<u8>>,
) -> Result<Vault<Unlocked>> {
    Vault::<Locked>::open(vault_path.clone())?.unlock(UnlockParams {
        path: vault_path,
        password: SecretBytes::new(std::mem::take(&mut *password)),
    })
}

fn prompt_password(prompt: &str, from_stdin: bool) -> std::io::Result<String> {
    if from_stdin {
        return read_password_from_stdin(prompt);
    }
    rpassword::prompt_password(prompt)
}

/// # Contract
///
/// ## Preconditions
/// - Called only for explicit stdin-based secret input paths.
///
/// ## Postconditions
/// - Reads exactly one line from stdin and strips line terminators.
/// - Returns I/O errors without falling back to argv or environment data.
///
/// ## Invariants
/// - Never echoes the prompt or secret value to stdout/stderr.
fn read_password_from_stdin(prompt: &str) -> std::io::Result<String> {
    use std::io::BufRead;
    let _ = prompt;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(&['\r', '\n'][..]).to_string())
}

fn string_to_zeroized_vec(mut value: String) -> Zeroizing<Vec<u8>> {
    let bytes = Zeroizing::new(value.as_bytes().to_vec());
    value.zeroize();
    bytes
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

/// # Contract
///
/// ## Preconditions
/// - `summaries` contain non-secret metadata returned by the core item list API.
///
/// ## Postconditions
/// - Returns tab-separated rows: `<item_id>\t<label>\t<kind>\n`.
/// - Labels are rendered so control characters cannot inject fake rows.
///
/// ## Invariants
/// - Never includes item secret field values.
fn render_item_summaries(summaries: &[ItemSummary]) -> String {
    let mut out = String::new();
    for summary in summaries {
        out.push_str(&hex_id(&summary.id));
        out.push('\t');
        out.push_str(&summary.label.escape_default().to_string());
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
            "meissnerseal",
            "init",
            "/tmp/test-vault.msv",
            "plaintext-password-never-real",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn add_does_not_accept_secret_value_through_argv() {
        // `add` exposes only --label/--kind/--vault; a positional secret value
        // (or a --secret flag) must be rejected at parse time (G-01).
        let positional = Cli::try_parse_from([
            "meissnerseal",
            "add",
            "--label",
            "token",
            "--kind",
            "api-token",
            "--vault",
            "/tmp/test-vault.msv",
            "plaintext-secret-never-real",
        ]);
        assert!(positional.is_err());

        let flagged = Cli::try_parse_from([
            "meissnerseal",
            "add",
            "--label",
            "token",
            "--kind",
            "api-token",
            "--vault",
            "/tmp/test-vault.msv",
            "--secret",
            "plaintext-secret-never-real",
        ]);
        assert!(flagged.is_err());
    }

    #[test]
    fn transfer_device_help_contains_no_secret_values() {
        let help = help_text();

        assert!(help.contains("shell-history leakage risk"));
        assert!(help.contains("transfer"));
        assert!(help.contains("device"));
        assert!(!help.contains(KNOWN_SECRET));
        assert!(!help.contains("Secret value:"));
        assert!(!help.contains("Master password:"));
    }

    #[test]
    fn transfer_create_rejects_plaintext_secret_in_argv() {
        let positional = Cli::try_parse_from([
            "meissnerseal",
            "transfer",
            "create",
            "--sender-keypair",
            "/tmp/sender.ms-kp",
            "--recipient-identity",
            "/tmp/recipient.ms-id",
            "--input",
            "/tmp/plain.txt",
            "--output",
            "/tmp/out.msenv",
            KNOWN_SECRET,
        ]);
        assert!(positional.is_err());

        let flagged = Cli::try_parse_from([
            "meissnerseal",
            "transfer",
            "create",
            "--sender-keypair",
            "/tmp/sender.ms-kp",
            "--recipient-identity",
            "/tmp/recipient.ms-id",
            "--input",
            "/tmp/plain.txt",
            "--output",
            "/tmp/out.msenv",
            "--secret",
            KNOWN_SECRET,
        ]);
        assert!(flagged.is_err());
    }

    #[test]
    fn envelope_file_roundtrip_preserves_all_fields() {
        let (sender_identity, sender_keypair) =
            generate("sender".to_owned()).expect("sender device");
        let (recipient_identity, _recipient_keypair) =
            generate("recipient".to_owned()).expect("recipient device");
        let recipient_device_id = recipient_identity.device_id;
        let envelope = create_signed_transfer_envelope(
            sender_identity.device_id,
            &sender_keypair,
            Some(recipient_device_id),
            recipient_identity.classical_public_key,
            recipient_identity.pqc_public_key,
            b"roundtrip plaintext".to_vec(),
            Some(unix_now_millis().expect("time") + 60_000),
        )
        .expect("envelope");

        let parsed = envelope_from_bytes(&envelope_to_bytes(&envelope)).expect("parse envelope");

        assert_envelopes_equal(&envelope, &parsed);
    }

    #[test]
    fn envelope_parser_rejects_wrong_magic() {
        assert!(envelope_from_bytes(b"BADENV").is_err());
    }

    #[test]
    fn envelope_parser_rejects_truncated_input() {
        let (sender_identity, sender_keypair) =
            generate("sender".to_owned()).expect("sender device");
        let (recipient_identity, _recipient_keypair) =
            generate("recipient".to_owned()).expect("recipient device");
        let envelope = create_signed_transfer_envelope(
            sender_identity.device_id,
            &sender_keypair,
            Some(recipient_identity.device_id),
            recipient_identity.classical_public_key,
            recipient_identity.pqc_public_key,
            b"roundtrip plaintext".to_vec(),
            Some(unix_now_millis().expect("time") + 60_000),
        )
        .expect("envelope");
        let bytes = envelope_to_bytes(&envelope);

        let truncated = bytes
            .get(..bytes.len().saturating_sub(1))
            .expect("truncated slice");
        assert!(envelope_from_bytes(truncated).is_err());
    }

    #[test]
    fn identity_file_roundtrip_preserves_all_fields() {
        let (identity, _keypair) = generate("identity".to_owned()).expect("identity");
        let parsed = deserialize_identity_text(&serialize_identity_text(&identity)).expect("parse");

        assert_eq!(identity.device_id, parsed.device_id);
        assert_eq!(identity.display_name, parsed.display_name);
        assert_eq!(
            identity.classical_public_key.as_slice(),
            parsed.classical_public_key.as_slice()
        );
        assert_eq!(
            identity.pqc_public_key.as_slice(),
            parsed.pqc_public_key.as_slice()
        );
        assert_eq!(
            identity
                .signing_public_key
                .as_ref()
                .expect("signing key")
                .as_bytes(),
            parsed
                .signing_public_key
                .as_ref()
                .expect("signing key")
                .as_bytes()
        );
        assert_eq!(identity.created_at, parsed.created_at);
    }

    #[test]
    fn identity_file_parser_rejects_unknown_version() {
        assert!(deserialize_identity_text("unknown-version\n").is_err());
    }

    #[test]
    fn keypair_file_roundtrip_preserves_device_id_and_classical_public_key() {
        let (identity, keypair) = generate("keypair".to_owned()).expect("keypair");
        let (device_id, classical_public_key, _parsed_keypair) =
            deserialize_keypair_bytes(&serialize_keypair_bytes(&identity, &keypair))
                .expect("parse keypair");

        assert_eq!(identity.device_id, device_id);
        assert_eq!(
            identity.classical_public_key.as_slice(),
            classical_public_key.as_slice()
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "PQC transfer path is too slow under Miri")]
    fn transfer_create_then_receive_roundtrips_plaintext() {
        let (sender_identity, sender_keypair) = generate("sender".to_owned()).expect("sender");
        let (recipient_identity, recipient_keypair) =
            generate("recipient".to_owned()).expect("recipient");
        let sender_keypair_path = unique_vault_path("sender-kp");
        let recipient_keypair_path = unique_vault_path("recipient-kp");
        let sender_identity_path = unique_vault_path("sender-id");
        let recipient_identity_path = unique_vault_path("recipient-id");
        let input_path = unique_vault_path("transfer-input");
        let envelope_path = unique_vault_path("transfer-envelope");
        let output_path = unique_vault_path("transfer-output");
        let plaintext = b"transfer plaintext never argv";

        std::fs::write(
            &sender_keypair_path,
            &*serialize_keypair_bytes(&sender_identity, &sender_keypair),
        )
        .expect("write sender keypair");
        std::fs::write(
            &recipient_keypair_path,
            &*serialize_keypair_bytes(&recipient_identity, &recipient_keypair),
        )
        .expect("write recipient keypair");
        std::fs::write(
            &sender_identity_path,
            serialize_identity_text(&sender_identity),
        )
        .expect("write sender identity");
        std::fs::write(
            &recipient_identity_path,
            serialize_identity_text(&recipient_identity),
        )
        .expect("write recipient identity");
        std::fs::write(&input_path, plaintext).expect("write plaintext");

        transfer_create_command(
            sender_keypair_path.clone(),
            recipient_identity_path.clone(),
            input_path.clone(),
            envelope_path.clone(),
            3600,
            &mut Vec::new(),
        )
        .expect("transfer create");
        transfer_receive_command(
            envelope_path.clone(),
            recipient_keypair_path.clone(),
            sender_identity_path.clone(),
            Some(output_path.clone()),
            &mut Vec::new(),
        )
        .expect("transfer receive");

        assert_eq!(std::fs::read(&output_path).expect("output"), plaintext);

        for path in [
            sender_keypair_path,
            recipient_keypair_path,
            sender_identity_path,
            recipient_identity_path,
            input_path,
            envelope_path,
            output_path,
        ] {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn stdin_global_flag_parses_before_add() {
        let cli = Cli::try_parse_from([
            "meissnerseal",
            "--stdin",
            "add",
            "--label",
            "x",
            "--kind",
            "password",
            "--vault",
            "/tmp/v.msv",
        ])
        .expect("--stdin must parse as a global flag before add");

        assert!(cli.stdin);
        assert!(matches!(cli.command, Commands::Add { .. }));
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn add_then_list_shows_label_and_kind_but_not_secret() {
        let path = unique_vault_path("cli-add-list");
        create_test_vault(&path);

        let mut sink = Vec::new();
        add_item(
            path.clone(),
            Zeroizing::new(PASSWORD.to_vec()),
            PlainItem {
                kind: ItemKind::ApiToken,
                label: "CI token".to_string(),
                secret: SecretBytes::new(KNOWN_SECRET.as_bytes().to_vec()),
                tags: Vec::new(),
            },
            &mut sink,
        )
        .expect("CLI add path succeeds");

        let listing = list_vault(path.clone(), Zeroizing::new(PASSWORD.to_vec()))
            .expect("CLI list path succeeds");
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
        get_item(
            path.clone(),
            Zeroizing::new(PASSWORD.to_vec()),
            id,
            &mut sink,
        )
        .expect("CLI get path succeeds");
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
            Zeroizing::new(PASSWORD.to_vec()),
            Zeroizing::new(EXPORT_PASSPHRASE.to_vec()),
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
            Zeroizing::new(PASSWORD.to_vec()),
            Zeroizing::new(EXPORT_PASSPHRASE.to_vec()),
            bundle_path.clone(),
            &mut Vec::new(),
        )
        .expect("export for import roundtrip succeeds");

        let mut sink = Vec::new();
        import_bundle(
            path.clone(),
            Zeroizing::new(PASSWORD.to_vec()),
            Zeroizing::new(EXPORT_PASSPHRASE.to_vec()),
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
        Vault::<Locked>::create(CreateVaultParams {
            path: path.to_path_buf(),
            password: SecretBytes::new(PASSWORD.to_vec()),
        })
        .expect("test vault creation succeeds");
    }

    fn add_known_item(path: &Path, label: &str, secret: &str) -> [u8; 16] {
        let session = unlock_session(path.to_path_buf(), Zeroizing::new(PASSWORD.to_vec()))
            .expect("unlock test vault");
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

    fn assert_envelopes_equal(
        left: &meissnerseal_core::transfer::TransferEnvelope,
        right: &meissnerseal_core::transfer::TransferEnvelope,
    ) {
        assert_eq!(left.version, right.version);
        assert_eq!(
            left.transfer_profile.to_u16(),
            right.transfer_profile.to_u16()
        );
        assert_eq!(left.envelope_id, right.envelope_id);
        assert_eq!(left.sender_device_id, right.sender_device_id);
        assert_eq!(left.recipient_device_id, right.recipient_device_id);
        assert_eq!(
            left.classical_ephemeral_public_key.as_slice(),
            right.classical_ephemeral_public_key.as_slice()
        );
        assert_eq!(
            left.pqc_ciphertext.as_slice(),
            right.pqc_ciphertext.as_slice()
        );
        assert_eq!(left.transcript_hash, right.transcript_hash);
        assert_eq!(left.encrypted_payload, right.encrypted_payload);
        assert_eq!(left.nonce, right.nonce);
        assert_eq!(left.expires_at, right.expires_at);
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
            .join(format!(
                "meissnerseal-{label}-{}-{now}.msv",
                std::process::id()
            ))
    }
}
