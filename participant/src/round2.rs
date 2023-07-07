use crate::Logger;
use frost::{
    keys::KeyPackage,
    round1::{NonceCommitment, SigningCommitments, SigningNonces},
    round2::{self, SignatureShare},
    Error, Identifier, SigningPackage,
};
use frost_ed25519 as frost;
use hex::FromHex;
use std::io::BufRead;

// #[derive(Debug)]
pub struct Round2Config {
    pub message: Vec<u8>,
    pub signer_commitments: Vec<SigningCommitments>,
}

// TODO: refactor to generate config
// TODO: handle errors
pub fn round_2_request_inputs(
    signing_commitments: SigningCommitments,
    input: &mut impl BufRead,
    logger: &mut dyn Logger,
) -> Result<Round2Config, Error> {
    logger.log("=== Round 2 ===".to_string());

    logger.log("Number of signers:".to_string());

    let mut signers_input = String::new();

    input.read_line(&mut signers_input).unwrap();

    let signers = signers_input.trim().parse::<u16>().unwrap();

    logger.log("You will receive a message from the coordinator, please enter here:".to_string());

    let mut message_input = String::new();

    input.read_line(&mut message_input).unwrap();

    let message = hex::decode(message_input.trim()).unwrap();

    let mut commitments = vec![signing_commitments];

    for i in 2..=signers {
        logger.log("Identifier:".to_string());

        let mut identifier_input = String::new();

        input.read_line(&mut identifier_input).unwrap();

        let id_value = identifier_input.trim().parse::<u16>().unwrap();
        let identifier = Identifier::try_from(id_value).unwrap();

        logger.log(format!("Hiding commitment {}:", i));
        let mut hiding_commitment_input = String::new();

        input.read_line(&mut hiding_commitment_input).unwrap();
        let hiding_commitment = NonceCommitment::from_bytes(
            <[u8; 32]>::from_hex(hiding_commitment_input.trim()).unwrap(),
        )
        .unwrap();

        logger.log(format!("Binding commitment {}:", i));
        let mut binding_commitment_input = String::new();

        input.read_line(&mut binding_commitment_input).unwrap();
        let binding_commitment = NonceCommitment::from_bytes(
            <[u8; 32]>::from_hex(binding_commitment_input.trim()).unwrap(),
        )
        .unwrap();

        let signer_commitments =
            SigningCommitments::new(identifier, hiding_commitment, binding_commitment); // TODO: Add test for correct error to be returned on failing deserialisation

        commitments.push(signer_commitments);
    }

    Ok(Round2Config {
        message,
        signer_commitments: commitments,
    })
}

pub fn generate_signature(
    config: Round2Config,
    key_package: &KeyPackage,
    signing_nonces: &SigningNonces,
) -> Result<SignatureShare, Error> {
    let signing_package = SigningPackage::new(config.signer_commitments, &config.message);
    let signature = round2::sign(&signing_package, signing_nonces, key_package)?;
    Ok(signature)
}
