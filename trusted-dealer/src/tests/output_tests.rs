use frost::keys::IdentifierList;
use frost_ed25519 as frost;
use rand::thread_rng;

use crate::inputs::Config;
use crate::output::{print_values, Logger};
use crate::trusted_dealer_keygen::{split_secret, trusted_dealer_keygen};

struct TestLogger(Vec<String>);

impl Logger for TestLogger {
    fn log(&mut self, value: String) {
        self.0.push(value);
    }
}

#[test]
fn check_output_without_secret() {
    let mut test_logger = TestLogger(Vec::new());
    let mut rng = thread_rng();
    let config = Config {
        min_signers: 2,
        max_signers: 3,
        secret: Vec::new(),
    };
    let (shares, pubkeys) =
        trusted_dealer_keygen(&config, IdentifierList::Default, &mut rng).unwrap();

    print_values(&shares, &pubkeys, &mut test_logger); // TODO: do we need shares here?

    let public_key_package = serde_json::to_string(&pubkeys).unwrap();

    assert_eq!(
        test_logger.0[0],
        format!("Public key package:\n{}", public_key_package)
    );
}

#[test]
fn check_output_with_secret() {
    let mut test_logger = TestLogger(Vec::new());
    let mut rng = thread_rng();
    let secret: Vec<u8> = vec![
        123, 28, 51, 211, 245, 41, 29, 133, 222, 102, 72, 51, 190, 177, 173, 70, 159, 127, 182, 2,
        90, 14, 199, 139, 58, 121, 12, 110, 19, 169, 131, 4,
    ];
    let config = Config {
        min_signers: 2,
        max_signers: 3,
        secret,
    };
    let (shares, pubkeys) = split_secret(&config, IdentifierList::Default, &mut rng).unwrap();

    print_values(&shares, &pubkeys, &mut test_logger);

    let public_key_package = serde_json::to_string(&pubkeys).unwrap();

    assert_eq!(
        test_logger.0[0],
        format!("Public key package:\n{}", public_key_package)
    );
}

#[test]
fn check_output_with_large_num_of_signers() {
    let mut test_logger = TestLogger(Vec::new());
    let mut rng = thread_rng();
    let config = Config {
        min_signers: 10,
        max_signers: 20,
        secret: Vec::new(),
    };
    let (shares, pubkeys) =
        trusted_dealer_keygen(&config, IdentifierList::Default, &mut rng).unwrap();

    print_values(&shares, &pubkeys, &mut test_logger);

    let public_key_package = serde_json::to_string(&pubkeys).unwrap();

    assert_eq!(
        test_logger.0[0],
        format!("Public key package:\n{}", public_key_package)
    );
}

#[test]
fn check_output_with_secret_with_large_num_of_signers() {
    let mut test_logger = TestLogger(Vec::new());
    let mut rng = thread_rng();
    let secret: Vec<u8> = vec![
        123, 28, 51, 211, 245, 41, 29, 133, 222, 102, 72, 51, 190, 177, 173, 70, 159, 127, 182, 2,
        90, 14, 199, 139, 58, 121, 12, 110, 19, 169, 131, 4,
    ];
    let config = Config {
        min_signers: 10,
        max_signers: 20,
        secret,
    };
    let (shares, pubkeys) = split_secret(&config, IdentifierList::Default, &mut rng).unwrap();

    print_values(&shares, &pubkeys, &mut test_logger);

    let public_key_package = serde_json::to_string(&pubkeys).unwrap();

    assert_eq!(
        test_logger.0[0],
        format!("Public key package:\n{}", public_key_package)
    );
}
