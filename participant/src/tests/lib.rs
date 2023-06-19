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

    let config = Config {
        identifier,
        public_key,
    };

    let mut test_logger = TestLogger(Vec::new());

    let mut valid_input =
        "1\n929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509\n".as_bytes();
    let expected = request_inputs(&mut valid_input, &mut test_logger).unwrap();

    assert_eq!(expected, config);
}

#[test]
fn check_0_input_for_identifier() {
    let mut test_logger = TestLogger(Vec::new());

    let mut invalid_input =
        "0\n929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509\n".as_bytes();
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

    let mut invalid_input = "1\n123456\n".as_bytes();
    let expected = request_inputs(&mut invalid_input, &mut test_logger);

    assert!(expected.is_err());
    assert!(expected == Err(Error::MalformedVerifyingKey))
}
