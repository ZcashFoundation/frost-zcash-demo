use crate::inputs::Config;
use crate::tests::integration_test::signature_gen::generate_key_packages;
use crate::trusted_dealer_keygen::split_secret;
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
    let (shares, pubkeys) = trusted_dealer_keygen(&config, &mut rng).unwrap();
    let key_packages = generate_key_packages(shares);
    let (nonces, commitments) =
        signature_gen::generate_nonces_and_commitments(config.min_signers, &key_packages, &mut rng);
    let message = "message to sign".as_bytes();
    let comms = commitments.into_values().collect();
    let signing_package = frost::SigningPackage::new(comms, message);
    let signature_shares =
        signature_gen::generate_signature_shares(nonces, &key_packages, &signing_package);
    let group_signature =
        frost::aggregate(&signing_package, &signature_shares[..], &pubkeys).unwrap();
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
    let (shares, pubkeys) = trusted_dealer_keygen(&config, &mut rng).unwrap();
    let key_packages = generate_key_packages(shares);
    let (nonces, commitments) =
        signature_gen::generate_nonces_and_commitments(config.min_signers, &key_packages, &mut rng);
    let message = "message to sign".as_bytes();
    let comms = commitments.into_values().collect();
    let signing_package = frost::SigningPackage::new(comms, message);
    let signature_shares =
        signature_gen::generate_signature_shares(nonces, &key_packages, &signing_package);
    let group_signature =
        frost::aggregate(&signing_package, &signature_shares[..], &pubkeys).unwrap();
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
    let (shares, pubkeys) = split_secret(&secret_config, &mut rng).unwrap();
    let key_packages = generate_key_packages(shares);
    let (nonces, commitments) = signature_gen::generate_nonces_and_commitments(
        secret_config.min_signers,
        &key_packages,
        &mut rng,
    );
    let message = "message to sign".as_bytes();
    let comms = commitments.into_values().collect();
    let signing_package = frost::SigningPackage::new(comms, message);
    let signature_shares =
        signature_gen::generate_signature_shares(nonces, &key_packages, &signing_package);
    let group_signature =
        frost::aggregate(&signing_package, &signature_shares[..], &pubkeys).unwrap();
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
    let (shares, pubkeys) = split_secret(&secret_config, &mut rng).unwrap();
    let key_packages = generate_key_packages(shares);
    let (nonces, commitments) = signature_gen::generate_nonces_and_commitments(
        secret_config.min_signers,
        &key_packages,
        &mut rng,
    );
    let message = "message to sign".as_bytes();
    let comms = commitments.into_values().collect();
    let signing_package = frost::SigningPackage::new(comms, message);
    let signature_shares =
        signature_gen::generate_signature_shares(nonces, &key_packages, &signing_package);
    let group_signature =
        frost::aggregate(&signing_package, &signature_shares[..], &pubkeys).unwrap();
    let verify_signature = pubkeys.group_public().verify(message, &group_signature);

    assert!(verify_signature.is_ok());
}
