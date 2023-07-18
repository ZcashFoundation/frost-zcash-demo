// use frost::keys::{IdentifierList, KeyPackage, SecretShare};
// use frost::round1::{SigningCommitments, SigningNonces};
// use frost::round2::SignatureShare;
// use frost::{Identifier, SigningPackage};
// use frost_ed25519 as frost;

// use rand::rngs::ThreadRng;
// use rand::thread_rng;
// use std::collections::{BTreeMap, HashMap};

// // #[test]
// fn check_keygen_with_dealer() {
//     let mut rng = thread_rng();
//     let (shares, pubkeys) =
//         frost::keys::generate_with_dealer(3, 2, IdentifierList::Default, &mut rng).unwrap();
//     let key_packages = key_package(&shares);
//     let (nonces, commitments) = round_1(2, &mut rng, &key_packages);
//     let message = "i am a message".as_bytes();

//     let signing_packages = step_2()

//     let signature_shares = round_2(nonces, &key_packages, signing_packages);

//     let signing_packages = step_2()

//     // Coordinator

//     let config = Config {
//         message,
//         signing_package,
//         signature_shares,
//         pubkeys,
//     };

//     // let group_signature = aggregate_and_verify(config);

//     // let expected = aggregate(
//     //     config.signing_package,
//     //     config.signature_shares,
//     //     config.pubkeys,
//     // )
//     // .unwrap();

//     // assert!(group_signature.is_ok());
//     // assert!(group_signature == expected)
// }

// fn key_package(shares: &HashMap<Identifier, SecretShare>) -> HashMap<Identifier, KeyPackage> {
//     let mut key_packages: HashMap<_, _> = HashMap::new();

//     for (identifier, secret_share) in shares {
//         let key_package = frost::keys::KeyPackage::try_from(secret_share.clone()).unwrap();
//         key_packages.insert(*identifier, key_package);
//     }

//     key_packages
// }

// fn round_1(
//     min_signers: u16,
//     mut rng: &mut ThreadRng,
//     key_packages: &HashMap<Identifier, KeyPackage>,
// ) -> (
//     HashMap<Identifier, SigningNonces>,
//     BTreeMap<Identifier, SigningCommitments>,
// ) {
//     // Participant Round 1

//     let mut nonces_map = HashMap::new();
//     let mut commitments_map = BTreeMap::new();

//     for participant_index in 1..(min_signers + 1) {
//         let participant_identifier = participant_index.try_into().expect("should be nonzero");
//         let key_package = &key_packages[&participant_identifier];
//         let (nonces, commitments) = frost::round1::commit(key_package.secret_share(), &mut rng);
//         nonces_map.insert(participant_identifier, nonces);
//         commitments_map.insert(participant_identifier, commitments);
//     }
//     (nonces_map, commitments_map)
// }

// fn round_2(
//     nonces_map: HashMap<Identifier, SigningNonces>,
//     key_packages: &HashMap<Identifier, KeyPackage>,
//     signing_package: SigningPackage,
// ) -> HashMap<Identifier, SignatureShare> {
//     let mut signature_shares = HashMap::new();
//     for participant_identifier in nonces_map.keys() {
//         let key_package = &key_packages[participant_identifier];

//         let nonces = &nonces_map[participant_identifier];
//         let signature_share = frost::round2::sign(&signing_package, nonces, key_package).unwrap();
//         signature_shares.insert(*participant_identifier, signature_share);
//     }
//     signature_shares
// }
