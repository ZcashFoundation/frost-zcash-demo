use clap::Parser;
use tokio::io;

use dkg::{args::Args, cli::cli};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut reader = io::BufReader::new(io::stdin());
    let mut logger = io::stdout();

    if args.ciphersuite == "ed25519" {
        cli::<frost_ed25519::Ed25519Sha512>(&mut reader, &mut logger).await?;
    } else if args.ciphersuite == "redpallas" {
        cli::<reddsa::frost::redpallas::PallasBlake2b512>(&mut reader, &mut logger).await?;
    }

    Ok(())
}
