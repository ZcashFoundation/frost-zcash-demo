#[cfg(test)]
use frost::Identifier;
use frost::{
    keys::{
        KeyPackage, SecretShare, SigningShare, VerifiableSecretSharingCommitment, VerifyingShare,
    },
    VerifyingKey,
};
use frost_ed25519 as frost;
use hex::FromHex;
use participant::round1::{generate_key_package, request_inputs, Round1Config};

use participant::Logger;

const PUBLIC_KEY: &str = "adf6ab1f882d04988eadfaa52fb175bf37b6247785d7380fde3fb9d68032470d";
const GROUP_PUBLIC_KEY: &str = "087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e";
const SIGNING_SHARE: &str = "ceed7dd148a1a1ec2e65b50ecab6a7c453ccbd38c397c3506a540b7cf0dd9104";
const VSS_COMMITMENT: [&str; 3] = [
    "087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e",
    "926d5910e146dccb9148ca39dc7607f4f7123ff1c0ffaf109add1d165c568bf2",
    "291bb78d7e4ef124f5aa6a36cbcf8c276e70fbb4e208212e916d762fc42c1bbc",
];
const SECRET_SHARE_JSON: &str = r#"{"identifier":"0100000000000000000000000000000000000000000000000000000000000000","value":"ceed7dd148a1a1ec2e65b50ecab6a7c453ccbd38c397c3506a540b7cf0dd9104","commitment":["087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e","926d5910e146dccb9148ca39dc7607f4f7123ff1c0ffaf109add1d165c568bf2", "291bb78d7e4ef124f5aa6a36cbcf8c276e70fbb4e208212e916d762fc42c1bbc"],"ciphersuite":"FROST(Ed25519, SHA-512)"}"#;

pub struct TestLogger(Vec<String>);

impl Logger for TestLogger {
    fn log(&mut self, value: String) {
        self.0.push(value);
    }
}

#[test]
fn check_valid_round_1_inputs() {
    let config = Round1Config {
        secret_share: SecretShare::new(
            Identifier::try_from(1).unwrap(),
            SigningShare::deserialize(<[u8; 32]>::from_hex(SIGNING_SHARE).unwrap()).unwrap(),
            VerifiableSecretSharingCommitment::deserialize(
                VSS_COMMITMENT
                    .iter()
                    .map(|s| hex::decode(s).unwrap().try_into().unwrap())
                    .collect(),
            )
            .unwrap(),
        ),
    };

    let mut test_logger = TestLogger(Vec::new());

    let input = SECRET_SHARE_JSON;
    let mut valid_input = input.as_bytes();

    let expected = request_inputs(&mut valid_input, &mut test_logger).unwrap();

    assert_eq!(expected, config);
}

#[test]
fn check_0_input_for_identifier() {
    let mut test_logger = TestLogger(Vec::new());

    let input = r#"{"identifier":"0000000000000000000000000000000000000000000000000000000000000000","value":"ceed7dd148a1a1ec2e65b50ecab6a7c453ccbd38c397c3506a540b7cf0dd9104","commitment":["087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e","291bb78d7e4ef124f5aa6a36cbcf8c276e70fbb4e208212e916d762fc42c1bbc"],"ciphersuite":"FROST(Ed25519, SHA-512)"}"#;
    let mut invalid_input = input.as_bytes();

    let expected = request_inputs(&mut invalid_input, &mut test_logger);

    assert!(expected.is_err());
}

#[test]
fn check_invalid_length_signing_share() {
    let mut test_logger = TestLogger(Vec::new());

    let input = r#"{"identifier":"0100000000000000000000000000000000000000000000000000000000000000","value":"ed7dd148a1a1ec2e65b50ecab6a7c453ccbd38c397c3506a540b7cf0dd9104","commitment":["087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e","291bb78d7e4ef124f5aa6a36cbcf8c276e70fbb4e208212e916d762fc42c1bbc"],"ciphersuite":"FROST(Ed25519, SHA-512)"}"#;

    let mut invalid_input = input.as_bytes();

    let expected = request_inputs(&mut invalid_input, &mut test_logger);

    assert!(expected.is_err());
}

// TODO: Handle this error differently
#[test]
fn check_invalid_length_vss_commitment() {
    let mut test_logger = TestLogger(Vec::new());

    let input = r#"{"identifier":"0100000000000000000000000000000000000000000000000000000000000000","value":"ceed7dd148a1a1ec2e65b50ecab6a7c453ccbd38c397c3506a540b7cf0dd9104","commitment":["7e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e","291bb78d7e4ef124f5aa6a36cbcf8c276e70fbb4e208212e916d762fc42c1bbc"],"ciphersuite":"FROST(Ed25519, SHA-512)"}"#;

    let mut invalid_input = input.as_bytes();

    let expected = request_inputs(&mut invalid_input, &mut test_logger);
    assert!(expected.is_err())
}

#[test]
fn check_key_package_generation() {
    let config = Round1Config {
        secret_share: serde_json::from_str(SECRET_SHARE_JSON).unwrap(),
    };

    let expected = KeyPackage::new(
        Identifier::try_from(1).unwrap(),
        SigningShare::deserialize(<[u8; 32]>::from_hex(SIGNING_SHARE).unwrap()).unwrap(),
        VerifyingShare::deserialize(<[u8; 32]>::from_hex(PUBLIC_KEY).unwrap()).unwrap(),
        VerifyingKey::from_hex(GROUP_PUBLIC_KEY).unwrap(),
    );
    let key_package = generate_key_package(&config).unwrap();

    assert!(expected == key_package)
}

#[test]
fn check_key_package_generation_fails_with_invalid_secret_share() {
    let input = r#"{"identifier":"0100000000000000000000000000000000000000000000000000000000000000","value":"afc0ba51fd450297725f9efe714400d51a1180a273177b5dd8ad3b8cba41560d","commitment":["087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e","291bb78d7e4ef124f5aa6a36cbcf8c276e70fbb4e208212e916d762fc42c1bbc"],"ciphersuite":"FROST(Ed25519, SHA-512)"}"#;
    let config = Round1Config {
        secret_share: serde_json::from_str(input).unwrap(),
    };
    let key_package = generate_key_package(&config);
    assert!(key_package.is_err());
}

// #[test]
// fn check_print_values() {
//     let mut test_logger = TestLogger(Vec::new());
//     let signing_share =
//         SigningShare::deserialize(<[u8; 32]>::from_hex(SIGNING_SHARE).unwrap()).unwrap();
//     let mut rng = thread_rng();
//     let (nonces, commitments) = round1::commit(&signing_share, &mut rng);

//     print_values(commitments, &mut test_logger);

//     let log = [
//         "=== Round 1 ===".to_string(),
//         format!("Hiding nonce: {}", hex::encode(nonces.hiding().serialize())),
//         format!(
//             "Binding nonce: {}",
//             hex::encode(nonces.binding().serialize())
//         ),
//         format!(
//             "Hiding commitment: {}",
//             hex::encode(commitments.hiding().serialize())
//         ),
//         format!(
//             "Binding commitment: {}",
//             hex::encode(commitments.binding().serialize())
//         ),
//         "=== Round 1 Completed ===".to_string(),
//         "Please send your Hiding and Binding Commitments to the coordinator".to_string(),
//     ];
//     assert_eq!(test_logger.0, log)
// }
