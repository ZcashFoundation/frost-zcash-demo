use std::io;

use coordinator::cli::cli;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = Box::new(io::stdin().lock());
    let mut logger = io::stdout();
    cli(&mut reader, &mut logger)?;

    Ok(())
}

// Choose participants -> send message to those participants - gen message to send

// Choose message - receive commitments - build commitment list - send to participants

// Receive signature shares - aggregate - send to participants. signautre shares must be validated first

// Verify group signature
