use frost::{Error, Identifier};
use frost_ed25519 as frost;
use std::io::BufRead;

#[derive(Debug, PartialEq)]
pub struct Config {
    identifier: Identifier,
}

pub trait Logger {
    fn log(&mut self, value: String);
}

pub fn request_inputs(input: &mut impl BufRead, logger: &mut dyn Logger) -> Result<Config, Error> {
    logger.log("Your identifier:".to_string());

    let mut identifier_input = String::new();

    input.read_line(&mut identifier_input).unwrap();

    let identifier = identifier_input
        .trim()
        .parse::<u16>()
        .map_err(|_| Error::MalformedIdentifier)?;

    Ok(Config {
        identifier: Identifier::try_from(identifier)?,
    })
}

#[cfg(test)]
mod tests {
    use frost::Identifier;
    use frost_ed25519 as frost;

    use crate::{request_inputs, Config, Logger};

    pub struct TestLogger(Vec<String>);

    impl Logger for TestLogger {
        fn log(&mut self, value: String) {
            self.0.push(value);
        }
    }

    #[test]
    fn check_valid_input_for_identifier() {
        let config = Config {
            identifier: Identifier::try_from(1).unwrap(),
        };

        let mut test_logger = TestLogger(Vec::new());

        let mut valid_input = "1\n".as_bytes();
        let expected = request_inputs(&mut valid_input, &mut test_logger).unwrap();

        assert_eq!(expected, config);
    }

    #[test]
    fn check_0_input_for_identifier() {
        let mut test_logger = TestLogger(Vec::new());

        let mut invalid_input = "0\n".as_bytes();
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
}
