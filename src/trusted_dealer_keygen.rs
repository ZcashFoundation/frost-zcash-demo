use frost::keys::{PublicKeyPackage, SecretShare};
use frost::{Error, Identifier, SigningKey};
use frost_ed25519 as frost;
use rand::rngs::ThreadRng;
use std::collections::HashMap;

use crate::inputs::Config;

pub fn trusted_dealer_keygen(
    config: &Config,
    rng: &mut ThreadRng,
) -> Result<(HashMap<Identifier, SecretShare>, PublicKeyPackage), Error> {
    let (shares, pubkeys) =
        frost::keys::generate_with_dealer(config.max_signers, config.min_signers, rng)?;

    for (_k, v) in shares.clone() {
        frost::keys::KeyPackage::try_from(v)?;
    }

    Ok((shares, pubkeys))
}

pub fn split_secret(
    config: &Config,
    rng: &mut ThreadRng,
) -> Result<(HashMap<Identifier, SecretShare>, PublicKeyPackage), Error> {
    let secret_key = SigningKey::from_bytes(
        config
            .secret
            .clone()
            .try_into()
            .map_err(|_| Error::MalformedSigningKey)?,
    )?;
    let (shares, pubkeys) =
        frost::keys::split(&secret_key, config.max_signers, config.min_signers, rng)?;

    for (_k, v) in shares.clone() {
        frost::keys::KeyPackage::try_from(v)?;
    }

    Ok((shares, pubkeys))
}
