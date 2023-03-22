mod inputs;
#[cfg(test)]
mod tests;

use std::io;

use crate::inputs::{request_inputs, validate_inputs};

fn main() -> io::Result<()> {
    let config = request_inputs();

    let out = validate_inputs(&config);

    match out {
        Ok(_) => (),
        Err(e) => println!("An error occurred: {e}"),
    }

    Ok(())
}
