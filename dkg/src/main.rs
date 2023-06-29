mod cli;
mod inputs;

#[cfg(test)]
mod tests;

use std::io;

use crate::cli::cli;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = Box::new(io::stdin().lock());
    let mut logger = io::stdout();
    cli(&mut reader, &mut logger)?;

    Ok(())
}
