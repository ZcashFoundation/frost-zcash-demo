mod cli;
mod round1;
mod round2;

#[cfg(all(test, not(feature = "redpallas")))]
mod tests;

use cli::cli;

use std::io;

// TODO: Update to use exit codes
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = Box::new(io::stdin().lock());
    let mut logger = io::stdout();
    cli(&mut reader, &mut logger)?;

    Ok(())
}
