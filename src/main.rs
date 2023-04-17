mod inputs;
#[cfg(test)]
mod tests;
mod trusted_dealer_keygen;

use std::collections::HashMap;
use std::io;

use frost_ed25519 as frost;

use frost::keys::KeyPackage;
use frost::{Identifier, VerifyingKey};
use rand::thread_rng;

use crate::inputs::{request_inputs, validate_inputs};
use crate::trusted_dealer_keygen::trusted_dealer_keygen;

fn main() -> io::Result<()> {
    // TODO: error handling
    let config = request_inputs();
    let mut rng = thread_rng();

    let out = validate_inputs(&config);

    match out {
        Ok(_) => (),
        Err(e) => println!("An error occurred: {e}"),
    }

    // Print outputs
    let (key_packages, pubkeys) = trusted_dealer_keygen(config, &mut rng);

    print_values(key_packages, pubkeys.group_public);

    Ok(())
}

fn print_values(keys: HashMap<Identifier, KeyPackage>, group_public_key: VerifyingKey) {
    println!("Group public key: {:x?}", group_public_key.to_bytes());
    println!("---");

    for (k, v) in keys {
        println!("Participant {:?}", k);
        println!("Secret share: {:x?}", v.secret_share.to_bytes());
        println!("Public key: {:x?}", v.public.to_bytes());
        println!("---")
    }
}
