#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use frost::keys::IdentifierList;
use rand::thread_rng;
use std::io::{BufRead, Write};

use crate::args::Args;
use crate::inputs::{print_values, request_inputs};
use crate::trusted_dealer_keygen::{split_secret, trusted_dealer_keygen};

// Currently this uses the Default Identifiers
pub fn cli(
    args: &Args,
    input: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = request_inputs(args, input, logger)?;

    let mut rng = thread_rng();

    let keygen = if config.secret.is_empty() {
        trusted_dealer_keygen(&config, IdentifierList::Default, &mut rng)
    } else {
        split_secret(&config, IdentifierList::Default, &mut rng)
    };

    let (shares, pubkeys) = keygen?;

    print_values(args, &shares, &pubkeys, logger)?;

    Ok(())
}
