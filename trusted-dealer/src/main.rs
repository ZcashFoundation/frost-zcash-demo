mod cli;
mod inputs;
mod trusted_dealer_keygen;

#[cfg(test)]
mod tests;

use std::io;

use crate::cli::cli;

// TODO: Update to use exit codes
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = Box::new(io::stdin().lock());
    let mut logger = io::stdout();
    cli(&mut reader, &mut logger)?;

    Ok(())
}
