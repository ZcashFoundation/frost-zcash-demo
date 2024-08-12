use rand::thread_rng;
use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use frost_core::keys::{IdentifierList, PublicKeyPackage, SecretShare};
use frost_core::{Ciphersuite, Identifier};
use reddsa::frost::redpallas::keys::EvenY;

use crate::args::Args;
use crate::inputs::{print_values, request_inputs};
use crate::trusted_dealer_keygen::{split_secret, trusted_dealer_keygen};

// The redpallas ciphersuite, when used for generating Orchard spending key
// signatures, requires ensuring public key have an even Y coordinate. Since the
// code uses generics, this trait is used to convert if needed depending on the
// ciphersuite.
//
// If you are adding a new ciphersuite to this tool which does note require
// this, just implement it and the default implementation (which does nothing)
// will suffice. See below.
pub trait MaybeIntoEvenY: Ciphersuite {
    fn into_even_y(
        secret_shares_and_public_key_package: (
            BTreeMap<Identifier<Self>, SecretShare<Self>>,
            PublicKeyPackage<Self>,
        ),
    ) -> (
        BTreeMap<Identifier<Self>, SecretShare<Self>>,
        PublicKeyPackage<Self>,
    ) {
        secret_shares_and_public_key_package
    }
}

// A ciphersuite that does not need the conversion.
impl MaybeIntoEvenY for frost_ed25519::Ed25519Sha512 {}

impl MaybeIntoEvenY for reddsa::frost::redpallas::PallasBlake2b512 {
    fn into_even_y(
        (secret_shares, public_key_package): (
            BTreeMap<Identifier<Self>, SecretShare<Self>>,
            PublicKeyPackage<Self>,
        ),
    ) -> (
        BTreeMap<Identifier<Self>, SecretShare<Self>>,
        PublicKeyPackage<Self>,
    ) {
        let is_even = public_key_package.has_even_y();
        let public_key_package = public_key_package.into_even_y(Some(is_even));
        let secret_shares = secret_shares
            .iter()
            .map(|(i, s)| (*i, s.clone().into_even_y(Some(is_even))))
            .collect();
        (secret_shares, public_key_package)
    }
}

pub fn cli<C: Ciphersuite + 'static + MaybeIntoEvenY>(
    args: &Args,
    input: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = request_inputs::<C>(args, input, logger)?;

    let mut rng = thread_rng();

    let shares_and_package = if config.secret.is_empty() {
        trusted_dealer_keygen(&config, IdentifierList::<C>::Default, &mut rng)?
    } else {
        split_secret(&config, IdentifierList::<C>::Default, &mut rng)?
    };

    let (shares, pubkeys) = MaybeIntoEvenY::into_even_y(shares_and_package);

    print_values(args, &shares, &pubkeys, logger)?;

    Ok(())
}
