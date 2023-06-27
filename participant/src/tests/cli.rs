use crate::cli::cli;
use participant::Logger;

pub struct TestLogger(Vec<String>);

impl Logger for TestLogger {
    fn log(&mut self, value: String) {
        self.0.push(value);
    }
}

#[test]
fn check_cli() {
    let identifier = "1";
    let pub_key = "470f53fb724502bf5b851471e9f8317616fcc7be9405ccff3347c232a3052ce7";
    let group_pub_key = "42ae1baa1bce5a38c130e60aade154ec8775076e729881aba66dabd0c0ac6332";
    let signing_share = "1edfa2ebd280cba9a72f0bc027d21c30078c11f92e0c908addb958062c1ac900";
    let vss_commitment = "0342ae1baa1bce5a38c130e60aade154ec8775076e729881aba66dabd0c0ac6332393a813a6b47782f0fbe653593cbb7b0e0e13f01b54b801144545cb774c0fe5683d8bee3cd63b10523ccace10044869c56bce8a6061950f9aebd7f2e36249571";

    let input = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        identifier, pub_key, group_pub_key, signing_share, vss_commitment
    );
    let mut reader = input.as_bytes();
    let mut test_logger = TestLogger(Vec::new());
    cli(&mut reader, &mut test_logger);

    assert_eq!(
        test_logger.0[0],
        format!("Your identifier (this should be an integer between 1 and 65535):")
    );
    assert_eq!(test_logger.0[1], format!("Your public key:"));
    assert_eq!(test_logger.0[2], format!("The group public key:"));
    assert_eq!(test_logger.0[3], format!("Your secret share:"));
    assert_eq!(
        test_logger.0[4],
        format!("Your verifiable secret sharing commitment:")
    );
    assert_eq!(
        test_logger.0[5],
        format!("Key Package succesfully created.")
    )
}
