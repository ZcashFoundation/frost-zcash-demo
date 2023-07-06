use crate::cli::cli;
use frost::{keys::SigningShare, round1, Identifier};
use frost_ed25519 as frost;
use hex::FromHex;
use participant::Logger;
use rand::thread_rng;

pub struct TestLogger(Vec<String>);

impl Logger for TestLogger {
    fn log(&mut self, value: String) {
        self.0.push(value);
    }
}

#[test]
fn check_cli() {
    // Round 1 inputs
    let identifier = "1";
    let pub_key = "470f53fb724502bf5b851471e9f8317616fcc7be9405ccff3347c232a3052ce7";
    let group_pub_key = "42ae1baa1bce5a38c130e60aade154ec8775076e729881aba66dabd0c0ac6332";
    let signing_share = "1edfa2ebd280cba9a72f0bc027d21c30078c11f92e0c908addb958062c1ac900";
    let vss_commitment = "0342ae1baa1bce5a38c130e60aade154ec8775076e729881aba66dabd0c0ac6332393a813a6b47782f0fbe653593cbb7b0e0e13f01b54b801144545cb774c0fe5683d8bee3cd63b10523ccace10044869c56bce8a6061950f9aebd7f2e36249571";

    // Round 2 inputs
    let min_signers = "3";
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

    let input = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        identifier,
        pub_key,
        group_pub_key,
        signing_share,
        vss_commitment,
        min_signers,
        MESSAGE,
        identifier,
        MY_HIDING_COMMITMENT,
        MY_BINDING_COMMITMENT,
        IDENTIFIER_2,
        HIDING_COMMITMENT_2,
        BINDING_COMMITMENT_2,
        IDENTIFIER_3,
        HIDING_COMMITMENT_3,
        BINDING_COMMITMENT_3
    );
    let mut reader = input.as_bytes();
    let mut test_logger = TestLogger(Vec::new());
    cli(&mut reader, &mut test_logger);

    let mut rng = thread_rng();

    // We aren't testing randomness so this needs to be generated in the tests. TODO: mock the round1::commit function. To be improved in a later issue.
    let (nonces, commitments) = round1::commit(
        Identifier::try_from(1).unwrap(),
        &SigningShare::from_hex(&signing_share).unwrap(),
        &mut rng,
    );

    let _hiding_nonce = hex::encode(nonces.hiding().to_bytes());
    let _binding_nonce = hex::encode(nonces.binding().to_bytes());
    let _hiding_commitment = hex::encode(commitments.hiding().to_bytes());
    let _binding_commitment = hex::encode(commitments.binding().to_bytes());

    // let signature_share = hex::encode(sig_share.to_bytes());

    let log = [
        "Your identifier (this should be an integer between 1 and 65535):",
        "Your public key:",
        "The group public key:",
        "Your secret share:",
        "Your verifiable secret sharing commitment:",
        "Key Package succesfully created.",
        "=== Round 1 ===",
        "Hiding nonce: {}",
        "Binding nonce: {}",
        "Hiding commitment: {}",
        "Binding commitment: {}",
        "=== Round 1 Completed ===",
        "Please send your Hiding and Binding Commitments to the coordinator",
        "=== Round 2 ===",
        "Number of signers:",
        "You will receive a message from the coordinator, please enter here:",
        "Identifier:",
        "Hiding commitment 2:",
        "Binding commitment 2:",
        "Identifier:",
        "Hiding commitment 3:",
        "Binding commitment 3:",
        // "Signature share: {:?}", &signature_share,
        // "=== Round 2 Completed ==="
    ]
    .to_vec();

    assert_eq!(test_logger.0[0..7], log[0..7]);
    assert_eq!(test_logger.0[12..22], log[12..22]);
    // TODO: test nonce and commitment values
}
