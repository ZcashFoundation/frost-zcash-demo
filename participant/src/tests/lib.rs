use frost::{
    keys::{KeyPackage, SigningShare, VerifyingShare},
    round1::{self, NonceCommitment, SigningCommitments},
    VerifyingKey,
};
#[cfg(test)]
use frost::{Error, Identifier};
use frost_ed25519 as frost;
use hex::FromHex;
use participant::{
    generate_key_package, generate_signature, request_inputs, round_2_request_inputs, Round1Config,
    Round2Config,
};
use rand::thread_rng;

use crate::Logger;

pub struct TestLogger(Vec<String>);

impl Logger for TestLogger {
    fn log(&mut self, value: String) {
        self.0.push(value);
    }
}

const IDENTIFIER: &str = "1";
const PUBLIC_KEY: &str = "adf6ab1f882d04988eadfaa52fb175bf37b6247785d7380fde3fb9d68032470d";
const GROUP_PUBLIC_KEY: &str = "087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e";
const SIGNING_SHARE: &str = "ceed7dd148a1a1ec2e65b50ecab6a7c453ccbd38c397c3506a540b7cf0dd9104";
const VSS_COMMITMENT : &str = "03087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e926d5910e146dccb9148ca39dc7607f4f7123ff1c0ffaf109add1d165c568bf2291bb78d7e4ef124f5aa6a36cbcf8c276e70fbb4e208212e916d762fc42c1bbc";

#[test]
fn check_valid_round_1_inputs() {
    let config = Round1Config {
        identifier: Identifier::try_from(1).unwrap(),
        public_key: VerifyingShare::from_bytes(<[u8; 32]>::from_hex(PUBLIC_KEY).unwrap()).unwrap(),
        group_public_key: VerifyingKey::from_hex(GROUP_PUBLIC_KEY).unwrap(),
        signing_share: SigningShare::from_bytes(<[u8; 32]>::from_hex(SIGNING_SHARE).unwrap())
            .unwrap(),
        vss_commitment: hex::decode(VSS_COMMITMENT).unwrap(),
    };

    let mut test_logger = TestLogger(Vec::new());

    let input = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        IDENTIFIER, PUBLIC_KEY, GROUP_PUBLIC_KEY, SIGNING_SHARE, VSS_COMMITMENT
    );
    let mut valid_input = input.as_bytes();

    let expected = request_inputs(&mut valid_input, &mut test_logger).unwrap();

    assert_eq!(expected, config);
}

#[test]
fn check_0_input_for_identifier() {
    let mut test_logger = TestLogger(Vec::new());

    let invalid_identifier = "0";
    let input = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        invalid_identifier, PUBLIC_KEY, GROUP_PUBLIC_KEY, SIGNING_SHARE, VSS_COMMITMENT
    );
    let mut invalid_input = input.as_bytes();

    let expected = request_inputs(&mut invalid_input, &mut test_logger);

    assert!(expected.is_err());
}

#[test]
fn check_non_u16_input_for_identifier() {
    let mut test_logger = TestLogger(Vec::new());

    let invalid_identifier = "-1";
    let input = format!("{}\n", invalid_identifier);
    let mut invalid_input = input.as_bytes();

    let expected = request_inputs(&mut invalid_input, &mut test_logger);

    assert!(expected.is_err());
}

#[test]
fn check_invalid_length_public_key() {
    let mut test_logger = TestLogger(Vec::new());

    let invalid_public_key = "123456";
    let input = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        IDENTIFIER, invalid_public_key, GROUP_PUBLIC_KEY, SIGNING_SHARE, VSS_COMMITMENT
    );
    let mut invalid_input = input.as_bytes();

    let expected = request_inputs(&mut invalid_input, &mut test_logger);

    assert!(expected.is_err());
    assert!(expected == Err(Error::MalformedVerifyingKey))
}

#[test]
fn check_invalid_length_group_public_key() {
    let mut test_logger = TestLogger(Vec::new());

    let invalid_group_pub_key = "123456";
    let input = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        IDENTIFIER, PUBLIC_KEY, invalid_group_pub_key, SIGNING_SHARE, VSS_COMMITMENT
    );
    let mut invalid_input = input.as_bytes();

    let expected = request_inputs(&mut invalid_input, &mut test_logger);

    assert!(expected.is_err());
    assert!(expected == Err(Error::MalformedVerifyingKey))
}

#[test]
fn check_invalid_length_signing_share() {
    let mut test_logger = TestLogger(Vec::new());

    let invalid_signing_share = "123456";
    let input = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        IDENTIFIER, PUBLIC_KEY, GROUP_PUBLIC_KEY, invalid_signing_share, VSS_COMMITMENT
    );
    let mut invalid_input = input.as_bytes();

    let expected = request_inputs(&mut invalid_input, &mut test_logger);

    assert!(expected.is_err());
    assert!(expected == Err(Error::MalformedSigningKey))
}

// TODO: Handle this error differently
#[test]
#[should_panic]
fn check_invalid_length_vss_commitment() {
    let mut test_logger = TestLogger(Vec::new());

    let invalid_vss_commitment = "1234567";
    let input = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        IDENTIFIER, PUBLIC_KEY, GROUP_PUBLIC_KEY, SIGNING_SHARE, invalid_vss_commitment
    );
    let mut invalid_input = input.as_bytes();

    let _expected = request_inputs(&mut invalid_input, &mut test_logger);
}

#[test]
fn check_key_package_generation() {
    let config = Round1Config {
        identifier: Identifier::try_from(1).unwrap(),
        public_key: VerifyingShare::from_bytes(<[u8; 32]>::from_hex(PUBLIC_KEY).unwrap()).unwrap(),
        group_public_key: VerifyingKey::from_hex(GROUP_PUBLIC_KEY).unwrap(),
        signing_share: SigningShare::from_bytes(<[u8; 32]>::from_hex(SIGNING_SHARE).unwrap())
            .unwrap(),
        vss_commitment: hex::decode(VSS_COMMITMENT).unwrap(),
    };

    let expected = KeyPackage::new(
        config.identifier,
        config.signing_share,
        config.public_key,
        config.group_public_key,
    );
    let key_package = generate_key_package(&config).unwrap();

    assert!(expected == key_package)
}

#[test]
fn check_key_package_generation_fails_with_invalid_secret_share() {
    let incorrect_signing_share =
        "afc0ba51fd450297725f9efe714400d51a1180a273177b5dd8ad3b8cba41560d";
    let config = Round1Config {
        identifier: Identifier::try_from(1).unwrap(),
        public_key: VerifyingShare::from_bytes(<[u8; 32]>::from_hex(PUBLIC_KEY).unwrap()).unwrap(),
        group_public_key: VerifyingKey::from_hex(GROUP_PUBLIC_KEY).unwrap(),
        signing_share: SigningShare::from_bytes(
            <[u8; 32]>::from_hex(incorrect_signing_share).unwrap(),
        )
        .unwrap(),
        vss_commitment: hex::decode(VSS_COMMITMENT).unwrap(),
    };
    let key_package = generate_key_package(&config);
    assert!(key_package.is_err());
}

const MESSAGE: &str = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
const MY_HIDING_COMMITMENT: &str =
    "44105304351ceddc58e15ddea35b2cb48e60ced54ceb22c3b0e5d42d098aa1d8";
const MY_BINDING_COMMITMENT: &str =
    "b8274b18a12f2cef74ae42f876cec1e31daab5cb162f95a56cd2487409c9d1dd";
const IDENTIFIER_2: &str = "2";
const HIDING_COMMITMENT_2: &str =
    "30f3f03bd739024dc5b1e9d422745a7f32b0971d5cef302106b30bd9f5642d70";
const BINDING_COMMITMENT_2: &str =
    "a7ccae3750846fbd7d132efec85e96236a711b2097a6f03b1afa04f6029458cc";
const IDENTIFIER_3: &str = "3";
const HIDING_COMMITMENT_3: &str =
    "d31bd81ce216b1c83912803a574a0285796275cb8b14f6dc92c8b09a6951f0a2";
const BINDING_COMMITMENT_3: &str =
    "e1c863cfd08df775b6747ef2456e9bf9a03cc281a479a95261dc39137fcf0967";

#[test]
fn check_valid_round_2_inputs() {
    // TODO: refactor
    let my_signer_commitments = SigningCommitments::new(
        Identifier::try_from(1).unwrap(),
        NonceCommitment::from_bytes(<[u8; 32]>::from_hex(MY_HIDING_COMMITMENT).unwrap()).unwrap(),
        NonceCommitment::from_bytes(<[u8; 32]>::from_hex(MY_BINDING_COMMITMENT).unwrap()).unwrap(),
    );

    let signer_commitments_2 = SigningCommitments::new(
        Identifier::try_from(2).unwrap(),
        NonceCommitment::from_bytes(<[u8; 32]>::from_hex(HIDING_COMMITMENT_2).unwrap()).unwrap(),
        NonceCommitment::from_bytes(<[u8; 32]>::from_hex(BINDING_COMMITMENT_2).unwrap()).unwrap(),
    );
    let signer_commitments_3 = SigningCommitments::new(
        Identifier::try_from(3).unwrap(),
        NonceCommitment::from_bytes(<[u8; 32]>::from_hex(HIDING_COMMITMENT_3).unwrap()).unwrap(),
        NonceCommitment::from_bytes(<[u8; 32]>::from_hex(BINDING_COMMITMENT_3).unwrap()).unwrap(),
    );

    let config = Round2Config {
        message: hex::decode("15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673")
            .unwrap(),
        signer_commitments: vec![
            my_signer_commitments,
            signer_commitments_2,
            signer_commitments_3,
        ],
    };
    let mut test_logger = TestLogger(Vec::new());

    let input = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        "3",
        MESSAGE,
        IDENTIFIER_2,
        HIDING_COMMITMENT_2,
        BINDING_COMMITMENT_2,
        IDENTIFIER_3,
        HIDING_COMMITMENT_3,
        BINDING_COMMITMENT_3
    );
    let mut valid_input = input.as_bytes();

    let expected =
        round_2_request_inputs(my_signer_commitments, &mut valid_input, &mut test_logger).unwrap();

    assert_eq!(expected.message, config.message);
    // TODO: This is easily resolved in the latest release of Frost which includes the Debug trait
    // assert_eq!(expected.signer_commitments[&Identifier::try_from(1).unwrap()], config.signer_commitments[&Identifier::try_from(1).unwrap()]);
}

// TODO: test for invalid inputs

#[test]
fn check_sign() {
    let config = Round1Config {
        identifier: Identifier::try_from(1).unwrap(),
        public_key: VerifyingShare::from_bytes(<[u8; 32]>::from_hex(PUBLIC_KEY).unwrap()).unwrap(),
        group_public_key: VerifyingKey::from_hex(GROUP_PUBLIC_KEY).unwrap(),
        signing_share: SigningShare::from_bytes(<[u8; 32]>::from_hex(SIGNING_SHARE).unwrap())
            .unwrap(),
        vss_commitment: hex::decode(VSS_COMMITMENT).unwrap(),
    };

    let key_package = KeyPackage::new(
        config.identifier,
        config.signing_share,
        config.public_key,
        config.group_public_key,
    );

    let mut rng = thread_rng();

    // TODO: Nonce doesn't seem to be exported. Look into this to improve these tests
    let (nonces, my_commitments) = round1::commit(
        Identifier::try_from(1).unwrap(),
        &SigningShare::from_hex(SIGNING_SHARE).unwrap(),
        &mut rng,
    );

    let signer_commitments_2 = SigningCommitments::new(
        Identifier::try_from(2).unwrap(),
        NonceCommitment::from_bytes(<[u8; 32]>::from_hex(HIDING_COMMITMENT_2).unwrap()).unwrap(),
        NonceCommitment::from_bytes(<[u8; 32]>::from_hex(BINDING_COMMITMENT_2).unwrap()).unwrap(),
    );

    let signer_commitments_3 = SigningCommitments::new(
        Identifier::try_from(3).unwrap(),
        NonceCommitment::from_bytes(<[u8; 32]>::from_hex(HIDING_COMMITMENT_3).unwrap()).unwrap(),
        NonceCommitment::from_bytes(<[u8; 32]>::from_hex(BINDING_COMMITMENT_3).unwrap()).unwrap(),
    );

    let config = Round2Config {
        message: hex::decode("15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673")
            .unwrap(),
        signer_commitments: vec![my_commitments, signer_commitments_2, signer_commitments_3],
    };

    let signature = generate_signature(config, &key_package, &nonces);

    assert!(signature.is_ok()) // TODO: Should be able to test this more specifically when I remove randomness from the test
}
