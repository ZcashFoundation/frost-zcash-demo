use crate::inputs::Config;
use crate::tests::integration_test::signature_gen::{key_package, round_1, round_2};
use crate::trusted_dealer_keygen::split_secret;
use frost::aggregate;
use frost::keys::IdentifierList;
use frost_ed25519 as frost;
use rand::thread_rng;

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
    let (shares, pubkeys) =
        trusted_dealer_keygen(&config, IdentifierList::Default, &mut rng).unwrap();

    let key_packages = key_package(&shares);
    let (nonces, commitments) = round_1(config.min_signers, &mut rng, &key_packages);
    let message = "i am a message".as_bytes();
    let (signing_package, signature_shares) = round_2(nonces, &key_packages, commitments, message);
    let group_signature = aggregate(&signing_package, &signature_shares, &pubkeys).unwrap();
    let verify_signature = pubkeys.group_public().verify(message, &group_signature);

    assert!(verify_signature.is_ok());
}

#[test]
fn check_keygen_with_dealer_with_large_num_of_signers() {
    let mut rng = thread_rng();
    let config = Config {
        min_signers: 14,
        max_signers: 20,
        secret: Vec::new(),
    };
    let (shares, pubkeys) =
        trusted_dealer_keygen(&config, IdentifierList::Default, &mut rng).unwrap();

    let key_packages = key_package(&shares);
    let (nonces, commitments) = round_1(config.min_signers, &mut rng, &key_packages);
    let message = "i am a message".as_bytes();
    let (signing_package, signature_shares) = round_2(nonces, &key_packages, commitments, message);
    let group_signature = aggregate(&signing_package, &signature_shares, &pubkeys).unwrap();
    let verify_signature = pubkeys.group_public().verify(message, &group_signature);

    assert!(verify_signature.is_ok());
}

#[test]
fn check_keygen_with_dealer_with_secret() {
    let mut rng = thread_rng();
    let secret: Vec<u8> = vec![
        123, 28, 51, 211, 245, 41, 29, 133, 222, 102, 72, 51, 190, 177, 173, 70, 159, 127, 182, 2,
        90, 14, 199, 139, 58, 121, 12, 110, 19, 169, 131, 4,
    ];
    let secret_config = Config {
        min_signers: 2,
        max_signers: 3,
        secret,
    };

    let (shares, pubkeys) =
        split_secret(&secret_config, IdentifierList::Default, &mut rng).unwrap();
    let key_packages = key_package(&shares);
    let (nonces, commitments) = round_1(secret_config.min_signers, &mut rng, &key_packages);
    let message = "i am a message".as_bytes();
    let (signing_package, signature_shares) = round_2(nonces, &key_packages, commitments, message);
    let group_signature = aggregate(&signing_package, &signature_shares, &pubkeys).unwrap();
    let verify_signature = pubkeys.group_public().verify(message, &group_signature);

    assert!(verify_signature.is_ok());
}

#[test]
fn check_keygen_with_dealer_with_secret_with_large_num_of_signers() {
    let mut rng = thread_rng();
    let secret: Vec<u8> = vec![
        123, 28, 51, 211, 245, 41, 29, 133, 222, 102, 72, 51, 190, 177, 173, 70, 159, 127, 182, 2,
        90, 14, 199, 139, 58, 121, 12, 110, 19, 169, 131, 4,
    ];
    let secret_config = Config {
        min_signers: 14,
        max_signers: 20,
        secret,
    };
    let (shares, pubkeys) =
        split_secret(&secret_config, IdentifierList::Default, &mut rng).unwrap();
    let key_packages = key_package(&shares);
    let (nonces, commitments) = round_1(secret_config.min_signers, &mut rng, &key_packages);
    let message = "i am a message".as_bytes();
    let (signing_package, signature_shares) = round_2(nonces, &key_packages, commitments, message);
    let group_signature = aggregate(&signing_package, &signature_shares, &pubkeys).unwrap();
    let verify_signature = pubkeys.group_public().verify(message, &group_signature);

    assert!(verify_signature.is_ok());
}
