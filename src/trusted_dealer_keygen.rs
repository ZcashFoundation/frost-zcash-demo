use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::Identifier;
use frost_ed25519 as frost;
use rand::rngs::ThreadRng;
use std::collections::HashMap;

use crate::inputs::Config;

pub fn trusted_dealer_keygen(
    config: Config,
    rng: &mut ThreadRng,
) -> (HashMap<Identifier, KeyPackage>, PublicKeyPackage) {
    let (shares, pubkeys) =
        frost::keys::keygen_with_dealer(config.max_signers, config.min_signers, rng).unwrap(); // TODO: handle error

    let key_packages: HashMap<_, _> = shares
        .into_iter()
        .map(|share| Ok((share.identifier, frost::keys::KeyPackage::try_from(share)?)))
        .collect::<Result<_, frost::Error>>()
        .unwrap(); // TODO: handle error

    (key_packages, pubkeys)
}
