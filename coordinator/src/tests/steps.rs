#![cfg(test)]

use coordinator::{
    args::{Args, ProcessedArgs},
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
use std::{collections::BTreeMap, io::BufWriter};

use super::common::get_helpers;
use super::common::Helpers;

fn build_pub_key_package() -> (BTreeMap<Identifier, VerifyingShare>, VerifyingKey) {
    let Helpers {
        public_key_1,
        public_key_2,
        public_key_3,
        verifying_key,
        ..
    } = get_helpers();

    let id_1 = Identifier::try_from(1).unwrap();
    let id_2 = Identifier::try_from(2).unwrap();
    let id_3 = Identifier::try_from(3).unwrap();

    let mut signer_pubkeys = BTreeMap::new();
    signer_pubkeys.insert(
        id_1,
        VerifyingShare::deserialize(&hex::decode(public_key_1).unwrap()).unwrap(),
    );
    signer_pubkeys.insert(
        id_2,
        VerifyingShare::deserialize(&hex::decode(public_key_2).unwrap()).unwrap(),
    );
    signer_pubkeys.insert(
        id_3,
        VerifyingShare::deserialize(&hex::decode(public_key_3).unwrap()).unwrap(),
    );

    let group_public = VerifyingKey::deserialize(&hex::decode(verifying_key).unwrap()).unwrap();

    (signer_pubkeys, group_public)
}

fn build_signing_commitments() -> BTreeMap<Identifier, SigningCommitments> {
    let Helpers {
        hiding_commitment_1,
        binding_commitment_1,
        hiding_commitment_3,
        binding_commitment_3,
        ..
    } = get_helpers();

    let id_1 = Identifier::try_from(1).unwrap();
    let id_3 = Identifier::try_from(3).unwrap();

    let signer_commitments_1 = SigningCommitments::new(
        NonceCommitment::deserialize(&hex::decode(hiding_commitment_1).unwrap()).unwrap(),
        NonceCommitment::deserialize(&hex::decode(binding_commitment_1).unwrap()).unwrap(),
    );
    let signer_commitments_3 = SigningCommitments::new(
        NonceCommitment::deserialize(&hex::decode(hiding_commitment_3).unwrap()).unwrap(),
        NonceCommitment::deserialize(&hex::decode(binding_commitment_3).unwrap()).unwrap(),
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
    let Helpers {
        participant_id_1,
        participant_id_3,
        pub_key_package,
        commitments_input_1,
        commitments_input_3,
        ..
    } = get_helpers();

    let mut comms = CLIComms::new();
    let args = Args::default();
    let mut buf = BufWriter::new(Vec::new());

    // -- INPUTS --

    let num_of_participants = 2u16;

    let signing_commitments = build_signing_commitments();

    let input = format!("{}\n{}\n", num_of_participants, pub_key_package);

    let pargs = ProcessedArgs::new(&args, &mut input.as_bytes(), &mut buf).unwrap();

    let input = format!(
        "{}\n{}\n{}\n{}\n",
        participant_id_1, commitments_input_1, participant_id_3, commitments_input_3
    );
    let mut buf = BufWriter::new(Vec::new());

    let (signer_pub_keys, group_public) = build_pub_key_package();

    let expected_participants_config = ParticipantsConfig {
        commitments: signing_commitments.clone(),
        pub_key_package: PublicKeyPackage::new(signer_pub_keys, group_public),
    };

    let participants_config = step_1(&pargs, &mut comms, &mut input.as_bytes(), &mut buf).await;

    assert!(participants_config.unwrap() == expected_participants_config);
}

// Input required:
// 1. message
// 2. number of signers
// 3. commitments for all signers
#[tokio::test]
async fn check_step_2() {
    let Helpers {
        commitments_from_part_1,
        commitments_from_part_3,
        signing_package_helper,
        message,
        pub_key_package,
        ..
    } = get_helpers();

    let args = Args::default();
    let mut buf = BufWriter::new(Vec::new());

    let input = format!(
        "2\n{}\n{}\n{}\n{}\n",
        pub_key_package, message, commitments_from_part_1, commitments_from_part_3
    );
    let pargs = ProcessedArgs::new(&args, &mut input.as_bytes(), &mut buf).unwrap();

    let signing_commitments = build_signing_commitments();

    let message = hex::decode(message).unwrap();

    let expected_signing_package = SigningPackage::new(signing_commitments.clone(), &message);

    let mut buf = BufWriter::new(Vec::new());
    let signing_package = step_2(&pargs, &mut buf, signing_commitments.clone()).unwrap();

    assert!(signing_package == expected_signing_package);

    let expected = format!("Signing Package:\n{}\n", signing_package_helper);

    let (_, res) = &buf.into_parts();
    let actual = String::from_utf8(res.as_ref().unwrap().to_owned()).unwrap();

    assert_eq!(expected, actual)
}

// // Input required:
// // 1. number of signers (TODO: maybe pass this in?)
// // 2. signatures for all signers
#[tokio::test]
async fn check_step_3() {
    let Helpers {
        participant_id_1,
        participant_id_3,
        signature_1,
        signature_3,
        group_signature,
        message,
        pub_key_package,
        ..
    } = get_helpers();

    let mut comms = CLIComms::new();
    let mut buf = BufWriter::new(Vec::new());
    let args = Args::default();

    let input = format!("2\n{}\n{}\n", pub_key_package, message);
    let pargs = ProcessedArgs::new(&args, &mut input.as_bytes(), &mut buf).unwrap();

    // keygen output

    let (signer_pubkeys, group_public) = build_pub_key_package();

    // step 2 input

    let input = format!("{}\n{}\n", signature_1, signature_3);

    let mut valid_input = input.as_bytes();

    let commitments = build_signing_commitments();

    let participants_config = ParticipantsConfig {
        commitments: commitments.clone(),
        pub_key_package: PublicKeyPackage::new(signer_pubkeys, group_public),
    };

    let message = hex::decode(message).unwrap();

    let signing_package = SigningPackage::new(commitments, &message);

    // step 3 generate signature

    let mut buf = BufWriter::new(Vec::new());
    step_3(
        &pargs,
        &mut comms,
        &mut valid_input,
        &mut buf,
        participants_config,
        &signing_package,
    )
    .await
    .unwrap();

    let expected = format!("Please enter JSON encoded signature shares for participant {}:\nPlease enter JSON encoded signature shares for participant {}:\nGroup signature: \"{}\"\n", participant_id_1, participant_id_3, group_signature);

    let (_, res) = &buf.into_parts();
    let actual = String::from_utf8(res.as_ref().unwrap().to_owned()).unwrap();

    assert_eq!(expected, actual)
}
