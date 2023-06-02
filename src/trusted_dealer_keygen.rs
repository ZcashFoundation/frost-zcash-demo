use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::{Error, Identifier};
use frost_ed25519 as frost;
use rand::rngs::ThreadRng;
use std::collections::HashMap;

use crate::inputs::Config;

pub fn trusted_dealer_keygen(
    config: &Config,
    rng: &mut ThreadRng,
) -> Result<(HashMap<Identifier, KeyPackage>, PublicKeyPackage), Error> {
    let (shares, pubkeys) =
        frost::keys::generate_with_dealer(config.max_signers, config.min_signers, rng)?;

    let mut key_packages: HashMap<_, _> = HashMap::new();

    for (k, v) in shares {
        let key_package = frost::keys::KeyPackage::try_from(v)?;
        key_packages.insert(k, key_package);
    }

    Ok((key_packages, pubkeys))
}

pub fn _split_secret(_config: Config, _rng: &mut ThreadRng) {}
