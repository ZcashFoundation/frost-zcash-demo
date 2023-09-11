#[cfg(test)]
mod tests;

use std::io;

use trusted_dealer::cli::cli;

// TODO: Update to use exit codes
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = Box::new(io::stdin().lock());
    let mut logger = io::stdout();
    cli(&mut reader, &mut logger)?;

    Ok(())
}
