use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "arcanum",
    about = "Local-first critical secrets vault with hybrid post-quantum-ready transfer",
    version,
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
    Init,
    /// Add a secret item (input via prompt or --stdin)
    Add,
    /// List item IDs and types (no secret values)
    List,
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
    let _cli = Cli::parse();
    eprintln!("arcanum: alpha — do not store real secrets yet.");
}
