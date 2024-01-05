#[cfg(all(test, not(feature = "redpallas")))]
mod tests;

use clap::Parser;
use participant::args::Args;
use participant::cli::cli;

use std::io;

// TODO: Update to use exit codes
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut reader = Box::new(io::stdin().lock());
    let mut logger = io::stdout();
    cli(&args, &mut reader, &mut logger).await?;

    Ok(())
}
