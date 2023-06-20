use frost::VerifyingKey;
#[cfg(test)]
use frost::{Error, Identifier};
use frost_ed25519 as frost;
use hex::FromHex;
use participant::{request_inputs, Config};

use crate::Logger;

pub struct TestLogger(Vec<String>);

impl Logger for TestLogger {
    fn log(&mut self, value: String) {
        self.0.push(value);
    }
}

const VSS_COMMITMENT : &str = "0353e4f0ed77543d021eb12cac53c35d4d99f5fc0fa5c3dfd82a3e1e296fba01bdcad2a298d93b5f0079f5f3874599ca2295482e9a4fa75be6c6deb273b61ee441e30ae9f78c1b56a4648130417247826afe3499c0d80b449740f8c968c64df0a4";

#[test]
fn check_valid_inputs() {
    let public_key = "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509";
    let identifier = 1;
    let group_public_key = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
    let signing_share = "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d";

    let config = Config {
        identifier: Identifier::try_from(identifier).unwrap(),
        public_key: <[u8; 32]>::from_hex(public_key).unwrap(),
        group_public_key: VerifyingKey::from_hex(group_public_key).unwrap(),
        signing_share: <[u8; 32]>::from_hex(signing_share).unwrap(),
        vss_commitment: hex::decode(VSS_COMMITMENT).unwrap(),
    };

    let mut test_logger = TestLogger(Vec::new());

    let input = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        identifier, public_key, group_public_key, signing_share, VSS_COMMITMENT
    );
    let mut valid_input = input.as_bytes();

    let expected = request_inputs(&mut valid_input, &mut test_logger).unwrap();

    assert_eq!(expected, config);
}

#[test]
fn check_0_input_for_identifier() {
    let mut test_logger = TestLogger(Vec::new());

    let identifier = "0";
    let pub_key = "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509";
    let group_pub_key = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
    let signing_share = "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d";
    let input = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        identifier, pub_key, group_pub_key, signing_share, VSS_COMMITMENT
    );
    let mut invalid_input = input.as_bytes();

    let expected = request_inputs(&mut invalid_input, &mut test_logger);

    assert!(expected.is_err());
}

#[test]
fn check_non_u16_input_for_identifier() {
    let mut test_logger = TestLogger(Vec::new());

    let mut invalid_input = "-1\n".as_bytes();
    let expected = request_inputs(&mut invalid_input, &mut test_logger);

    assert!(expected.is_err());
}

#[test]
fn check_invalid_length_public_key() {
    let mut test_logger = TestLogger(Vec::new());

    let identifier = "1";
    let pub_key = "123456";
    let group_pub_key = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
    let signing_share = "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d";
    let input = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        identifier, pub_key, group_pub_key, signing_share, VSS_COMMITMENT
    );
    let mut invalid_input = input.as_bytes();

    let expected = request_inputs(&mut invalid_input, &mut test_logger);

    assert!(expected.is_err());
    assert!(expected == Err(Error::MalformedVerifyingKey))
}

#[test]
fn check_invalid_length_group_public_key() {
    let mut test_logger = TestLogger(Vec::new());

    let identifier = "1";
    let pub_key = "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509";
    let group_pub_key = "123456";
    let signing_share = "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d";
    let input = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        identifier, pub_key, group_pub_key, signing_share, VSS_COMMITMENT
    );
    let mut invalid_input = input.as_bytes();

    let expected = request_inputs(&mut invalid_input, &mut test_logger);

    assert!(expected.is_err());
    assert!(expected == Err(Error::MalformedVerifyingKey))
}

#[test]
fn check_invalid_length_signing_share() {
    let mut test_logger = TestLogger(Vec::new());

    let identifier = "1";
    let pub_key = "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509";
    let group_pub_key = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
    let signing_share = "123456";
    let input = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        identifier, pub_key, group_pub_key, signing_share, VSS_COMMITMENT
    );
    let mut invalid_input = input.as_bytes();

    let expected = request_inputs(&mut invalid_input, &mut test_logger);

    assert!(expected.is_err());
    assert!(expected == Err(Error::MalformedSigningKey))
}
