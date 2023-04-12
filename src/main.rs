mod inputs;
mod keygen;
#[cfg(test)]
mod tests;

use std::io;

use keygen::{keygen, Output};

use crate::inputs::{request_inputs, validate_inputs};

fn main() -> io::Result<()> {
    // TODO: error handling
    let config = request_inputs();

    let out = validate_inputs(&config);

    match out {
        Ok(_) => (),
        Err(e) => println!("An error occurred: {e}"),
    }

    // Print outputs
    let keygen = keygen(config).unwrap();

    print_values(keygen);

    Ok(())
}

fn print_values(output: Output) {
    println!("Group public key: {:?}", output.group_public_key.to_bytes());
}
