use frost_core::keys::IdentifierList;
use frost_core::Ciphersuite;
use rand::thread_rng;
use std::io::{BufRead, Write};

use crate::args::Args;
use crate::inputs::{print_values, request_inputs};
use crate::trusted_dealer_keygen::{split_secret, trusted_dealer_keygen};

// Currently this uses the Default Identifiers
pub fn cli<C: Ciphersuite + 'static>(
    args: &Args,
    input: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = request_inputs::<C>(args, input, logger)?;

    let mut rng = thread_rng();

    let keygen = if config.secret.is_empty() {
        trusted_dealer_keygen(&config, IdentifierList::<C>::Default, &mut rng)
    } else {
        split_secret(&config, IdentifierList::<C>::Default, &mut rng)
    };

    let (shares, pubkeys) = keygen?;

    print_values(args, &shares, &pubkeys, logger)?;

    Ok(())
}
