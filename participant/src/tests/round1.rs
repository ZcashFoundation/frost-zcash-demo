use frost::{
    keys::{KeyPackage, SigningShare, VerifyingShare},
    VerifyingKey,
};
#[cfg(test)]
use frost::{Error, Identifier};
use frost_ed25519 as frost;
use hex::FromHex;
use participant::round1::{generate_key_package, request_inputs, Round1Config};

use participant::Logger;

const IDENTIFIER: &str = "1";
const PUBLIC_KEY: &str = "adf6ab1f882d04988eadfaa52fb175bf37b6247785d7380fde3fb9d68032470d";
const GROUP_PUBLIC_KEY: &str = "087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e";
const SIGNING_SHARE: &str = "ceed7dd148a1a1ec2e65b50ecab6a7c453ccbd38c397c3506a540b7cf0dd9104";
const VSS_COMMITMENT : &str = "03087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e926d5910e146dccb9148ca39dc7607f4f7123ff1c0ffaf109add1d165c568bf2291bb78d7e4ef124f5aa6a36cbcf8c276e70fbb4e208212e916d762fc42c1bbc";

pub struct TestLogger(Vec<String>);

impl Logger for TestLogger {
    fn log(&mut self, value: String) {
        self.0.push(value);
    }
}

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
