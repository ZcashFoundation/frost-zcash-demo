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
    let identifier: u16 = 1;
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

    // We aren't testing randomness so we are not testing the generation of the nonces and commitments at the top level.
    // TODO: mock the round1::commit function. To be improved in a later issue.

    let log = [
        "Your identifier (this should be an integer between 1 and 65535):".to_string(),
        "Your public key:".to_string(),
        "The group public key:".to_string(),
        "Your secret share:".to_string(),
        "Your verifiable secret sharing commitment:".to_string(),
        "Key Package succesfully created.".to_string(),
        "=== Round 1 ===".to_string(),
    ];

    assert_eq!(test_logger.0[0..=6], log)
}
