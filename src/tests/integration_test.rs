use crate::inputs::Config;
use frost_ed25519 as frost;
use rand::thread_rng;

use crate::trusted_dealer_keygen::_split_secret;
use crate::trusted_dealer_keygen::trusted_dealer_keygen;
mod signature_gen;

#[test]
fn check_keygen_with_dealer() {
    let mut rng = thread_rng();
    let config = Config {
        min_signers: 2,
        max_signers: 3,
        secret: Vec::new(),
    };
    let (key_packages, pubkeys) = trusted_dealer_keygen(&config, &mut rng).unwrap();
    let (nonces, commitments) =
        signature_gen::generate_nonces_and_commitments(config.min_signers, &key_packages, &mut rng);
    let message = "message to sign".as_bytes();
    let comms = commitments.into_values().collect();
    let signing_package = frost::SigningPackage::new(comms, message.to_vec());
    let signature_shares =
        signature_gen::generate_signature_shares(nonces, &key_packages, &signing_package);
    let group_signature =
        frost::aggregate(&signing_package, &signature_shares[..], &pubkeys).unwrap();
    let verify_signature = pubkeys.group_public.verify(message, &group_signature);

    assert!(verify_signature.is_ok());
}

#[test]
fn check_keygen_with_dealer_with_secret() {
    let mut rng = thread_rng();
    let secret_config = Config {
        min_signers: 2,
        max_signers: 3,
        secret: b"byte".to_vec(),
    };
    _split_secret(secret_config, &mut rng);
}
