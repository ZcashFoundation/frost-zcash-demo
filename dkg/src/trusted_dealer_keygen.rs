// use frost::keys::dkg::round1::{Package, SecretPackage};
// use frost::Error;
// use frost_ed25519 as frost;
// use rand::rngs::ThreadRng;

// use crate::inputs::Config;

// #[cfg(test)]
// mod tests {

//     use rand::thread_rng;

//     use crate::{inputs::Config, trusted_dealer_keygen::split_secret};

//     #[test]
//     fn return_malformed_signing_key_error_if_secret_is_invalid() {
//         let mut rng = thread_rng();
//         let secret_config = Config {
//             min_signers: 2,
//             max_signers: 3,
//             secret: b"helloIamaninvalidsecret111111111".to_vec(),
//         };

//         let out = split_secret(&secret_config, &mut rng);

//         assert!(out.is_err());
//     }

//     #[test]
//     fn return_malformed_signing_key_error_if_secret_is_invalid_type() {
//         let mut rng = thread_rng();
//         let secret: Vec<u8> = vec![
//             123, 28, 51, 211, 245, 41, 29, 133, 222, 102, 72, 51, 190, 177, 173, 70, 159, 127, 182,
//             2, 90, 14, 199, 139, 58, 121, 12, 110, 19, 169, 131,
//         ];
//         let secret_config = Config {
//             min_signers: 2,
//             max_signers: 3,
//             secret,
//         };

//         let out = split_secret(&secret_config, &mut rng);

//         assert!(out.is_err());
//     }
// }
