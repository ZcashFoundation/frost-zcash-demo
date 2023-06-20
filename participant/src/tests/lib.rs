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

#[test]
fn check_valid_inputs() {
    let public_key =
        <[u8; 32]>::from_hex("929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509")
            .unwrap();
    let identifier = Identifier::try_from(1).unwrap();
    let group_public_key =
        VerifyingKey::from_hex("15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673")
            .unwrap();

    let config = Config {
        identifier,
        public_key,
        group_public_key,
    };

    let mut test_logger = TestLogger(Vec::new());

    let identifier = "1";
    let pub_key = "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509";
    let group_pub_key = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
    let input = format!("{}\n{}\n{}\n", identifier, pub_key, group_pub_key);
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
    let input = format!("{}\n{}\n{}\n", identifier, pub_key, group_pub_key);
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
    let input = format!("{}\n{}\n{}\n", identifier, pub_key, group_pub_key);
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
    let input = format!("{}\n{}\n{}\n", identifier, pub_key, group_pub_key);
    let mut invalid_input = input.as_bytes();

    let expected = request_inputs(&mut invalid_input, &mut test_logger);

    assert!(expected.is_err());
    assert!(expected == Err(Error::MalformedVerifyingKey))
}
