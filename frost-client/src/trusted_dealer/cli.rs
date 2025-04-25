use rand::thread_rng;
use std::io::{BufRead, Write};

use frost_core::Ciphersuite;

use super::args::Args;
use super::inputs::{print_values, request_inputs};
use super::trusted_dealer::{trusted_dealer, MaybeIntoEvenY};

pub fn cli<C: Ciphersuite + 'static + MaybeIntoEvenY>(
    args: &Args,
    input: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = request_inputs::<C>(args, input, logger)?;

    let mut rng = thread_rng();

    let (shares, pubkeys) = trusted_dealer(&config, &mut rng)?;

    print_values::<C>(args, &shares, &pubkeys, logger)?;

    Ok(())
}
