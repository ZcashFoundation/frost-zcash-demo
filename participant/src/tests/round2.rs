// use std::collections::BTreeMap;

// #[cfg(test)]
// use frost::Identifier;
// use frost::{
//     keys::{KeyPackage, SigningShare, VerifyingShare},
//     round1::{self, NonceCommitment, SigningCommitments},
//     round2::SignatureShare,
//     VerifyingKey,
// };
// use frost_ed25519 as frost;
// use hex::FromHex;
// use participant::round2::{generate_signature, round_2_request_inputs, Round2Config};
// use participant::Logger;
// use participant::{round1::Round1Config, round2::print_values_round_2};
// use rand::thread_rng;

// pub struct TestLogger(Vec<String>);

// impl Logger for TestLogger {
//     fn log(&mut self, value: String) {
//         self.0.push(value);
//     }
// }

// const PUBLIC_KEY: &str = "adf6ab1f882d04988eadfaa52fb175bf37b6247785d7380fde3fb9d68032470d";
// const GROUP_PUBLIC_KEY: &str = "087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e";
// const SIGNING_SHARE: &str = "ceed7dd148a1a1ec2e65b50ecab6a7c453ccbd38c397c3506a540b7cf0dd9104";
// const VSS_COMMITMENT : &str = "03087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e926d5910e146dccb9148ca39dc7607f4f7123ff1c0ffaf109add1d165c568bf2291bb78d7e4ef124f5aa6a36cbcf8c276e70fbb4e208212e916d762fc42c1bbc";
// const MESSAGE: &str = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
// const MY_HIDING_COMMITMENT: &str =
//     "44105304351ceddc58e15ddea35b2cb48e60ced54ceb22c3b0e5d42d098aa1d8";
// const MY_BINDING_COMMITMENT: &str =
//     "b8274b18a12f2cef74ae42f876cec1e31daab5cb162f95a56cd2487409c9d1dd";
// const IDENTIFIER_2: &str = "2";
// const HIDING_COMMITMENT_2: &str =
//     "30f3f03bd739024dc5b1e9d422745a7f32b0971d5cef302106b30bd9f5642d70";
// const BINDING_COMMITMENT_2: &str =
//     "a7ccae3750846fbd7d132efec85e96236a711b2097a6f03b1afa04f6029458cc";
// const IDENTIFIER_3: &str = "3";
// const HIDING_COMMITMENT_3: &str =
//     "d31bd81ce216b1c83912803a574a0285796275cb8b14f6dc92c8b09a6951f0a2";
// const BINDING_COMMITMENT_3: &str =
//     "e1c863cfd08df775b6747ef2456e9bf9a03cc281a479a95261dc39137fcf0967";

// #[test]
// fn check_valid_round_2_inputs() {
//     // TODO: refactor
//     let my_signer_commitments = SigningCommitments::new(
//         NonceCommitment::deserialize(<[u8; 32]>::from_hex(MY_HIDING_COMMITMENT).unwrap()).unwrap(),
//         NonceCommitment::deserialize(<[u8; 32]>::from_hex(MY_BINDING_COMMITMENT).unwrap()).unwrap(),
//     );

//     let signer_commitments_2 = SigningCommitments::new(
//         NonceCommitment::deserialize(<[u8; 32]>::from_hex(HIDING_COMMITMENT_2).unwrap()).unwrap(),
//         NonceCommitment::deserialize(<[u8; 32]>::from_hex(BINDING_COMMITMENT_2).unwrap()).unwrap(),
//     );
//     let signer_commitments_3 = SigningCommitments::new(
//         NonceCommitment::deserialize(<[u8; 32]>::from_hex(HIDING_COMMITMENT_3).unwrap()).unwrap(),
//         NonceCommitment::deserialize(<[u8; 32]>::from_hex(BINDING_COMMITMENT_3).unwrap()).unwrap(),
//     );

//     let mut signer_commitments = BTreeMap::new();
//     signer_commitments.insert(Identifier::try_from(1).unwrap(), my_signer_commitments);
//     signer_commitments.insert(Identifier::try_from(2).unwrap(), signer_commitments_2);
//     signer_commitments.insert(Identifier::try_from(3).unwrap(), signer_commitments_3);

//     let config = Round2Config {
//         message: hex::decode("15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673")
//             .unwrap(),
//         signer_commitments,
//     };

//     let mut test_logger = TestLogger(Vec::new());

//     let input = format!(
//         "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
//         "3",
//         MESSAGE,
//         IDENTIFIER_2,
//         HIDING_COMMITMENT_2,
//         BINDING_COMMITMENT_2,
//         IDENTIFIER_3,
//         HIDING_COMMITMENT_3,
//         BINDING_COMMITMENT_3
//     );
//     let mut valid_input = input.as_bytes();

//     let expected = round_2_request_inputs(
//         Identifier::try_from(1).unwrap(),
//         my_signer_commitments,
//         &mut valid_input,
//         &mut test_logger,
//     )
//     .unwrap();

//     assert_eq!(expected.message, config.message);
//     // TODO: This is easily resolved in the latest release of Frost which includes the Debug trait
//     // assert_eq!(expected.signer_commitments[&Identifier::try_from(1).unwrap()], config.signer_commitments[&Identifier::try_from(1).unwrap()]);
// }

// // TODO: test for invalid inputs

// #[test]
// fn check_sign() {
//     let config = Round1Config {
//         identifier: Identifier::try_from(1).unwrap(),
//         public_key: VerifyingShare::deserialize(<[u8; 32]>::from_hex(PUBLIC_KEY).unwrap()).unwrap(),
//         group_public_key: VerifyingKey::from_hex(GROUP_PUBLIC_KEY).unwrap(),
//         signing_share: SigningShare::deserialize(<[u8; 32]>::from_hex(SIGNING_SHARE).unwrap())
//             .unwrap(),
//         vss_commitment: hex::decode(VSS_COMMITMENT).unwrap(),
//     };

//     let key_package = KeyPackage::new(
//         config.identifier,
//         config.signing_share,
//         config.public_key,
//         config.group_public_key,
//     );

//     let mut rng = thread_rng();

//     // TODO: Nonce doesn't seem to be exported. Look into this to improve these tests
//     let (nonces, my_commitments) =
//         round1::commit(&SigningShare::from_hex(SIGNING_SHARE).unwrap(), &mut rng);

//     let signer_commitments_2 = SigningCommitments::new(
//         NonceCommitment::deserialize(<[u8; 32]>::from_hex(HIDING_COMMITMENT_2).unwrap()).unwrap(),
//         NonceCommitment::deserialize(<[u8; 32]>::from_hex(BINDING_COMMITMENT_2).unwrap()).unwrap(),
//     );

//     let signer_commitments_3 = SigningCommitments::new(
//         NonceCommitment::deserialize(<[u8; 32]>::from_hex(HIDING_COMMITMENT_3).unwrap()).unwrap(),
//         NonceCommitment::deserialize(<[u8; 32]>::from_hex(BINDING_COMMITMENT_3).unwrap()).unwrap(),
//     );

//     let mut signer_commitments = BTreeMap::new();
//     signer_commitments.insert(Identifier::try_from(1).unwrap(), my_commitments);
//     signer_commitments.insert(Identifier::try_from(2).unwrap(), signer_commitments_2);
//     signer_commitments.insert(Identifier::try_from(3).unwrap(), signer_commitments_3);

//     let config = Round2Config {
//         message: hex::decode("15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673")
//             .unwrap(),
//         signer_commitments,
//     };

//     let signature = generate_signature(config, &key_package, &nonces);

//     assert!(signature.is_ok()) // TODO: Should be able to test this more specifically when I remove randomness from the test
// }

// #[test]
// fn check_print_values_round_2() {
//     let mut test_logger = TestLogger(Vec::new());

//     const SIGNATURE_SHARE: &str =
//         "44055c54d0604cbd006f0d1713a22474d7735c5e8816b1878f62ca94bf105900";
//     let signature_response =
//         SignatureShare::deserialize(<[u8; 32]>::from_hex(SIGNATURE_SHARE).unwrap()).unwrap();

//     print_values_round_2(signature_response, &mut test_logger);

//     let log = [
//         "Please send the following to the Coordinator".to_string(),
//         format!("Signature share: {}", SIGNATURE_SHARE),
//         "=== End of Round 2 ===".to_string(),
//     ];

//     assert_eq!(test_logger.0, log);
// }
