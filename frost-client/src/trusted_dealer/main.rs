use std::io;

use clap::Parser;

use frost_client::trusted_dealer::{args::Args, cli::cli};

// TODO: Update to use exit codes
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut reader = Box::new(io::stdin().lock());
    let mut logger = io::stdout();
    if args.ciphersuite == "ed25519" {
        cli::<frost_ed25519::Ed25519Sha512>(&args, &mut reader, &mut logger)?;
    } else if args.ciphersuite == "redpallas" {
        cli::<reddsa::frost::redpallas::PallasBlake2b512>(&args, &mut reader, &mut logger)?;
    }

    Ok(())
}
