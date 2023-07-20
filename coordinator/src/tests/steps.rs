// Test values from https://github.com/ZcashFoundation/frost/blob/main/frost-ed25519/tests/helpers/vectors.json

// // Input required:
// // 1. public key package
// // 2. number of signparticipantsers
// // 3. identifiers for all signers
// #[test]
// fn check_step_1() {
// }

// // Input required:
// // 1. message
// // 2. number of signers
// // 3. commitments for all signers
// #[test]
// fn check_step_2() {
// }

use crate::{step_1::ParticipantsConfig, step_3::step_3};
use frost::{
    keys::{PublicKeyPackage, VerifyingShare},
    round1::{NonceCommitment, SigningCommitments},
    Identifier, SigningPackage, VerifyingKey,
};
use frost_ed25519 as frost;
use hex::FromHex;
use std::{
    collections::{BTreeMap, HashMap},
    io::BufWriter,
};

// // Input required:
// // 1. number of signers (TODO: maybe pass this in?)
// // 2. signatures for all signers
#[test]
fn check_step_3() {
    let mut buf = BufWriter::new(Vec::new());

    let id_1 = Identifier::try_from(1).unwrap();
    let id_3 = Identifier::try_from(3).unwrap();

    const PUBLIC_KEY_1: &str = "fc2c9b8e335c132d9ebe0403c9317aac480bbbf8cbdb1bc3730bb68eb60dadf9";
    const PUBLIC_KEY_3: &str = "2cff4148a2f965801fb1f25f1d2a4e5df2f75b3a57cd06f30471c2c774419a41";
    const GROUP_PUBLIC_KEY: &str =
        "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";

    let mut signer_pubkeys = HashMap::new();
    signer_pubkeys.insert(
        id_1,
        VerifyingShare::deserialize(<[u8; 32]>::from_hex(PUBLIC_KEY_1).unwrap()).unwrap(),
    );
    signer_pubkeys.insert(
        id_3,
        VerifyingShare::deserialize(<[u8; 32]>::from_hex(PUBLIC_KEY_3).unwrap()).unwrap(),
    );

    let group_public = VerifyingKey::from_hex(GROUP_PUBLIC_KEY).unwrap();

    let signature_1 = "{\"share\":\"b97409beff18861f0959530db091a64b812e3fefaa87e1e3d2c039f11d96cc09\",\"ciphersuite\":\"FROST(Ed25519, SHA-512)\"}";
    let signature_3 = "{\"share\":\"9816a14e7cdecfcb240976f564cf98c5640e596b6ddf270379efbef4e9f7db0b\",\"ciphersuite\":\"FROST(Ed25519, SHA-512)\"}";

    let input = format!("{}\n{}\n", signature_1, signature_3);

    let mut valid_input = input.as_bytes();

    let participants_config = ParticipantsConfig {
        participants: vec![id_1, id_3],
        pub_key_package: PublicKeyPackage::new(signer_pubkeys, group_public),
    };
    const HIDING_COMMITMENT_1: &str =
        "5078f5c6d679654bb88a8887242d49cc21a553ed26caed4d52570c6656fb9b92";
    const BINDING_COMMITMENT_1: &str =
        "936b660d3008d8298b0a7220a327a0813ffedd9d07604bdc73d7cffef63c0da0";
    const HIDING_COMMITMENT_3: &str =
        "91c2469b501fe5af8493f9ae77c8f57999460af317f2d9f2d4378ae0e665860e";
    const BINDING_COMMITMENT_3: &str =
        "c225618accff2266a45d87dc3219b04c774ca26c8629c4fa483e7e87da820007";

    let signer_commitments_1 = SigningCommitments::new(
        NonceCommitment::deserialize(<[u8; 32]>::from_hex(HIDING_COMMITMENT_1).unwrap()).unwrap(),
        NonceCommitment::deserialize(<[u8; 32]>::from_hex(BINDING_COMMITMENT_1).unwrap()).unwrap(),
    );
    let signer_commitments_3 = SigningCommitments::new(
        NonceCommitment::deserialize(<[u8; 32]>::from_hex(HIDING_COMMITMENT_3).unwrap()).unwrap(),
        NonceCommitment::deserialize(<[u8; 32]>::from_hex(BINDING_COMMITMENT_3).unwrap()).unwrap(),
    );

    let mut signing_commitments = BTreeMap::new();
    signing_commitments.insert(id_1, signer_commitments_1);
    signing_commitments.insert(id_3, signer_commitments_3);

    let signing_package = SigningPackage::new(signing_commitments, b"test");

    step_3(
        &mut valid_input,
        &mut buf,
        participants_config,
        signing_package,
    );

    let expected = "Please enter JSON encoded signatures for participant Identifier(\"0100000000000000000000000000000000000000000000000000000000000000\"):\nPlease enter JSON encoded signatures for participant Identifier(\"0300000000000000000000000000000000000000000000000000000000000000\"):\nGroup signature: \"72c948a63797c693e8e978fdb703a1f5a7590472a539da13b71dd6c2b8c1b2a664b7b4af6194439357c5d15f366760fce53c985a186709e74bb0f8e5078ea805\"\n";

    let (_, res) = &buf.into_parts();
    let actual = hex::encode(res.as_ref().unwrap());

    assert_eq!(hex::encode(expected), actual)
}
