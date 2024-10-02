use frost_core::{self as frost, Ciphersuite};

use frost::keys::{IdentifierList, PublicKeyPackage, SecretShare};
use frost::{Error, Identifier, SigningKey};
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;

use crate::inputs::Config;

#[allow(clippy::type_complexity)]
pub fn trusted_dealer_keygen<C: Ciphersuite, R: RngCore + CryptoRng>(
    config: &Config,
    identifiers: IdentifierList<C>,
    rng: &mut R,
) -> Result<(BTreeMap<Identifier<C>, SecretShare<C>>, PublicKeyPackage<C>), Error<C>> {
    let (shares, pubkeys) = frost::keys::generate_with_dealer(
        config.max_signers,
        config.min_signers,
        identifiers,
        rng,
    )?;

    for (_k, v) in shares.clone() {
        frost::keys::KeyPackage::try_from(v)?;
    }

    Ok((shares, pubkeys))
}

#[allow(clippy::type_complexity)]
pub fn split_secret<C: Ciphersuite, R: RngCore + CryptoRng>(
    config: &Config,
    identifiers: IdentifierList<C>,
    rng: &mut R,
) -> Result<(BTreeMap<Identifier<C>, SecretShare<C>>, PublicKeyPackage<C>), Error<C>> {
    let secret_key = SigningKey::deserialize(&config.secret)?;
    let (shares, pubkeys) = frost::keys::split(
        &secret_key,
        config.max_signers,
        config.min_signers,
        identifiers,
        rng,
    )?;

    for (_k, v) in shares.clone() {
        frost::keys::KeyPackage::try_from(v)?;
    }

    Ok((shares, pubkeys))
}

#[cfg(test)]
mod tests {

    use frost_ed25519::keys::IdentifierList;
    use rand::thread_rng;

    use crate::{inputs::Config, trusted_dealer_keygen::split_secret};

    #[test]
    fn return_malformed_signing_key_error_if_secret_is_invalid() {
        let mut rng = thread_rng();
        let secret_config = Config {
            min_signers: 2,
            max_signers: 3,
            secret: b"helloIamaninvalidsecret111111111".to_vec(),
        };

        let out = split_secret(&secret_config, IdentifierList::Default, &mut rng);

        assert!(out.is_err());
    }

    #[test]
    fn return_malformed_signing_key_error_if_secret_is_invalid_type() {
        let mut rng = thread_rng();
        let secret: Vec<u8> = vec![
            123, 28, 51, 211, 245, 41, 29, 133, 222, 102, 72, 51, 190, 177, 173, 70, 159, 127, 182,
            2, 90, 14, 199, 139, 58, 121, 12, 110, 19, 169, 131,
        ];
        let secret_config = Config {
            min_signers: 2,
            max_signers: 3,
            secret,
        };

        let out = split_secret(&secret_config, IdentifierList::Default, &mut rng);

        assert!(out.is_err());
    }
}
