#[cfg(all(test, not(feature = "redpallas")))]
mod tests;

use std::io;

use clap::Parser;

use coordinator::{args::Args, cli::cli};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut reader = Box::new(io::stdin().lock());
    let mut logger = io::stdout();
    cli(&args, &mut reader, &mut logger).await?;

    Ok(())
}

// Choose participants -> send message to those participants - gen message to send

// Choose message - receive commitments - build commitment list - send to participants

// Receive signature shares - aggregate - send to participants. signautre shares must be validated first

// Verify group signature
