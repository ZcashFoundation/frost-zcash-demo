#[cfg(test)]
use coordinator::{
    args::Args,
    comms::cli::CLIComms,
    step_1::{step_1, ParticipantsConfig},
    step_2::step_2,
    step_3::step_3,
};
use frost::{
    keys::{PublicKeyPackage, VerifyingShare},
    round1::{NonceCommitment, SigningCommitments},
    Identifier, SigningPackage, VerifyingKey,
};
use frost_ed25519 as frost;
use hex::FromHex;
use std::{collections::BTreeMap, io::BufWriter};

// Test values from https://github.com/ZcashFoundation/frost/blob/main/frost-ed25519/tests/helpers/vectors.json

const PUBLIC_KEY_1: &str = "fc2c9b8e335c132d9ebe0403c9317aac480bbbf8cbdb1bc3730bb68eb60dadf9";
const PUBLIC_KEY_2: &str = "f7c3031debffbaf121022409d057e6e1034a532636301d12e26beddff58d05c7";
const PUBLIC_KEY_3: &str = "2cff4148a2f965801fb1f25f1d2a4e5df2f75b3a57cd06f30471c2c774419a41";
const GROUP_PUBLIC_KEY: &str = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";

fn build_pub_key_package() -> PublicKeyPackage {
    let id_1 = Identifier::try_from(1).unwrap();
    let id_2 = Identifier::try_from(2).unwrap();
    let id_3 = Identifier::try_from(3).unwrap();

    let mut signer_pubkeys = BTreeMap::new();
    signer_pubkeys.insert(
        id_1,
        VerifyingShare::deserialize(<[u8; 32]>::from_hex(PUBLIC_KEY_1).unwrap()).unwrap(),
    );
    signer_pubkeys.insert(
        id_2,
        VerifyingShare::deserialize(<[u8; 32]>::from_hex(PUBLIC_KEY_2).unwrap()).unwrap(),
    );
    signer_pubkeys.insert(
        id_3,
        VerifyingShare::deserialize(<[u8; 32]>::from_hex(PUBLIC_KEY_3).unwrap()).unwrap(),
    );

    let group_public =
        VerifyingKey::deserialize(<[u8; 32]>::from_hex(GROUP_PUBLIC_KEY).unwrap()).unwrap();

    PublicKeyPackage::new(signer_pubkeys, group_public)
}

fn build_signing_commitments() -> BTreeMap<Identifier, SigningCommitments> {
    let id_1 = Identifier::try_from(1).unwrap();
    let id_3 = Identifier::try_from(3).unwrap();

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

    signing_commitments

    // SigningPackage::new(signing_commitments, b"test")
}

// Input required:
// 1. public key package
// 2. number of signers
// 3. identifiers for all signers
#[tokio::test]
async fn check_step_1() {
    let mut comms = CLIComms {};
    let args = Args::default();
    let mut buf = BufWriter::new(Vec::new());

    let id_1 = Identifier::try_from(1).unwrap();
    let id_3 = Identifier::try_from(3).unwrap();

    // -- INPUTS --

    let pub_key_package = "{\"signer_pubkeys\":{\"0100000000000000000000000000000000000000000000000000000000000000\":\"fc2c9b8e335c132d9ebe0403c9317aac480bbbf8cbdb1bc3730bb68eb60dadf9\",  \"0200000000000000000000000000000000000000000000000000000000000000\":\"f7c3031debffbaf121022409d057e6e1034a532636301d12e26beddff58d05c7\",\"0300000000000000000000000000000000000000000000000000000000000000\":\"2cff4148a2f965801fb1f25f1d2a4e5df2f75b3a57cd06f30471c2c774419a41\"},\"group_public\":\"15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673\", \"ciphersuite\":\"FROST(Ed25519, SHA-512)\"}";

    let num_of_participants = 2;

    let id_input_1 = "0100000000000000000000000000000000000000000000000000000000000000";
    let id_input_3 = "0300000000000000000000000000000000000000000000000000000000000000";

    let input = format!(
        "{}\n{}\n{}\n{}\n",
        pub_key_package, num_of_participants, id_input_1, id_input_3
    );

    let mut valid_input = input.as_bytes();

    // --

    let expected = "Paste the JSON public key package: \nThe number of participants: \nIdentifier for participant 1 (hex encoded): \nIdentifier for participant 2 (hex encoded): \nSelected participants: \n\"0100000000000000000000000000000000000000000000000000000000000000\"\n\"0300000000000000000000000000000000000000000000000000000000000000\"\n";

    let (_, res) = &buf.into_parts();
    let actual = hex::encode(res.as_ref().unwrap());

    assert_eq!(hex::encode(expected), actual)
}

// Input required:
// 1. message
// 2. number of signers
// 3. commitments for all signers
#[tokio::test]
async fn check_step_2() {
    let mut comms = CLIComms {};
    let args = Args::default();
    let mut buf = BufWriter::new(Vec::new());

    // -- INPUTS --

    let message = "74657374";

    

    let commitments_input_1 = "{\"header\":{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"},\"identifier\":\"0100000000000000000000000000000000000000000000000000000000000000\",\"signing_share\":\"4ca8a14c31582e92770b23d8b4e5f253d94cbbdc34332cbbb9972f7d0a16a106\",\"commitment\":[\"c0b1eb84bc74624e9196a4ae01d7b784133dd714943001524e33f62ac09fe6df\",\"a4ed252f52e34077e990f70a743a261ff74cbda88173269cc1feeb0616af734b\",\"0fe7ced03a6d5cc4286d050f20fea6dbc14f412a430fc21f92ee2861011fb93c\"]}";
    let commitments_input_3 = "{\"header\":{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"},\"identifier\":\"0300000000000000000000000000000000000000000000000000000000000000\",\"signing_share\":\"4ca8a14c31582e92770b23d8b4e5f253d94cbbdc34332cbbb9972f7d0a16a106\",\"commitment\":[\"c0b1eb84bc74624e9196a4ae01d7b784133dd714943001524e33f62ac09fe6df\",\"a4ed252f52e34077e990f70a743a261ff74cbda88173269cc1feeb0616af734b\",\"0fe7ced03a6d5cc4286d050f20fea6dbc14f412a430fc21f92ee2861011fb93c\"]}";

    let input = format!(
        "{}\n{}\n{}\n",
        message, commitments_input_1, commitments_input_3
    );

    let mut valid_input = input.as_bytes();

    // --

    let id_1 = Identifier::try_from(1).unwrap();
    let id_3 = Identifier::try_from(3).unwrap();

    let signing_commitments = build_signing_commitments();

    let expected_signing_package = SigningPackage::new(signing_commitments.clone(), b"test");

    let signing_package = step_2(&mut valid_input, &mut buf, signing_commitments.clone());

    assert!(signing_package.is_ok());
    assert!(signing_package.unwrap() == expected_signing_package);

    let expected_participants_config = ParticipantsConfig {
        commitments: signing_commitments.clone(),
        pub_key_package: build_pub_key_package(),
    };

    let participants_config = step_1(&args, &mut comms, &mut valid_input, &mut buf);

    assert!(participants_config.await.unwrap() == expected_participants_config);

    let expected = "The message to be signed (hex encoded)\nPlease enter JSON encoded commitments for participant 0100000000000000000000000000000000000000000000000000000000000000:\nPlease enter JSON encoded commitments for participant 0300000000000000000000000000000000000000000000000000000000000000:\nSigning Package:\n{\"signing_commitments\":{\"0100000000000000000000000000000000000000000000000000000000000000\":{\"hiding\":\"5078f5c6d679654bb88a8887242d49cc21a553ed26caed4d52570c6656fb9b92\",\"binding\":\"936b660d3008d8298b0a7220a327a0813ffedd9d07604bdc73d7cffef63c0da0\",\"ciphersuite\":\"FROST(Ed25519, SHA-512)\"},\"0300000000000000000000000000000000000000000000000000000000000000\":{\"hiding\":\"91c2469b501fe5af8493f9ae77c8f57999460af317f2d9f2d4378ae0e665860e\",\"binding\":\"c225618accff2266a45d87dc3219b04c774ca26c8629c4fa483e7e87da820007\",\"ciphersuite\":\"FROST(Ed25519, SHA-512)\"}},\"message\":\"74657374\",\"ciphersuite\":\"FROST(Ed25519, SHA-512)\"}\n";

    let (_, res) = &buf.into_parts();
    let actual = String::from_utf8(res.as_ref().unwrap().to_owned()).unwrap();

    assert_eq!(expected, actual)
}

// // Input required:
// // 1. number of signers (TODO: maybe pass this in?)
// // 2. signatures for all signers
#[tokio::test]
async fn check_step_3() {
    let mut comms = CLIComms {};
    let args = Args::default();
    let mut buf = BufWriter::new(Vec::new());

    let id_1 = Identifier::try_from(1).unwrap();
    let id_3 = Identifier::try_from(3).unwrap();

    const PUBLIC_KEY_1: &str = "fc2c9b8e335c132d9ebe0403c9317aac480bbbf8cbdb1bc3730bb68eb60dadf9";
    const PUBLIC_KEY_3: &str = "2cff4148a2f965801fb1f25f1d2a4e5df2f75b3a57cd06f30471c2c774419a41";
    const GROUP_PUBLIC_KEY: &str =
        "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";

    let mut signer_pubkeys = BTreeMap::new();
    signer_pubkeys.insert(
        id_1,
        VerifyingShare::deserialize(<[u8; 32]>::from_hex(PUBLIC_KEY_1).unwrap()).unwrap(),
    );
    signer_pubkeys.insert(
        id_3,
        VerifyingShare::deserialize(<[u8; 32]>::from_hex(PUBLIC_KEY_3).unwrap()).unwrap(),
    );

    let group_public =
        VerifyingKey::deserialize(<[u8; 32]>::from_hex(GROUP_PUBLIC_KEY).unwrap()).unwrap();

    let signature_1 = "{\"share\":\"b97409beff18861f0959530db091a64b812e3fefaa87e1e3d2c039f11d96cc09\",\"ciphersuite\":\"FROST(Ed25519, SHA-512)\"}";
    let signature_3 = "{\"share\":\"9816a14e7cdecfcb240976f564cf98c5640e596b6ddf270379efbef4e9f7db0b\",\"ciphersuite\":\"FROST(Ed25519, SHA-512)\"}";

    let input = format!("{}\n{}\n", signature_1, signature_3);

    let mut valid_input = input.as_bytes();

    let commitments = build_signing_commitments();

    let participants_config = ParticipantsConfig {
        commitments: commitments.clone(),
        pub_key_package: PublicKeyPackage::new(signer_pubkeys, group_public),
    };
    let signing_package = SigningPackage::new(commitments, b"test");

    step_3(
        &mut comms,
        &mut valid_input,
        &mut buf,
        participants_config,
        &signing_package,
    );

    let expected = "Please enter JSON encoded signature shares for participant 0100000000000000000000000000000000000000000000000000000000000000:\nPlease enter JSON encoded signature shares for participant 0300000000000000000000000000000000000000000000000000000000000000:\nGroup signature: \"72c948a63797c693e8e978fdb703a1f5a7590472a539da13b71dd6c2b8c1b2a664b7b4af6194439357c5d15f366760fce53c985a186709e74bb0f8e5078ea805\"\n";

    let (_, res) = &buf.into_parts();
    let actual = String::from_utf8(res.as_ref().unwrap().to_owned()).unwrap();

    assert_eq!(expected, actual)
}
