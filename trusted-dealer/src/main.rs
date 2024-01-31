// TODO: fix and restore tests
// #[cfg(test)]
// mod tests;

use std::io;

use clap::Parser;

use trusted_dealer::{args::Args, cli::cli};

// TODO: Update to use exit codes
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut reader = Box::new(io::stdin().lock());
    let mut logger = io::stdout();
    cli(&args, &mut reader, &mut logger)?;

    Ok(())
}
