use crate::Logger;
use frost::{
    keys::KeyPackage,
    round1::{NonceCommitment, SigningCommitments, SigningNonces},
    round2::{self, SignatureShare},
    Error, Identifier, SigningPackage,
};
use frost_ed25519 as frost;
use hex::FromHex;
use std::{collections::BTreeMap, io::BufRead};

// #[derive(Debug)]
pub struct Round2Config {
    pub message: Vec<u8>,
    pub signer_commitments: BTreeMap<Identifier, SigningCommitments>,
}

// TODO: refactor to generate config
// TODO: handle errors
pub fn round_2_request_inputs(
    id: Identifier,
    signing_commitments: SigningCommitments,
    input: &mut impl BufRead,
    logger: &mut dyn Logger,
) -> Result<Round2Config, Error> {
    logger.log("=== Round 2 ===".to_string());

    logger.log("Number of signers:".to_string());

    let mut signers_input = String::new();

    input.read_line(&mut signers_input).unwrap();

    let signers = signers_input.trim().parse::<u16>().unwrap();

    logger.log("Enter the message to sign (received from the coordinator):".to_string());

    let mut message_input = String::new();

    input.read_line(&mut message_input).unwrap();

    let message = hex::decode(message_input.trim()).unwrap();

    let mut commitments = BTreeMap::new();
    commitments.insert(id, signing_commitments);

    for _ in 2..=signers {
        logger.log("Identifier:".to_string());

        let mut identifier_input = String::new();

        input.read_line(&mut identifier_input).unwrap();

        let id_value = identifier_input.trim().parse::<u16>().unwrap();
        let identifier = Identifier::try_from(id_value).unwrap();

        logger.log(format!("Hiding commitment {}:", id_value));
        let mut hiding_commitment_input = String::new();

        input.read_line(&mut hiding_commitment_input).unwrap();
        let hiding_commitment = NonceCommitment::deserialize(
            <[u8; 32]>::from_hex(hiding_commitment_input.trim()).unwrap(),
        )?;

        logger.log(format!("Binding commitment {}:", id_value));
        let mut binding_commitment_input = String::new();

        input.read_line(&mut binding_commitment_input).unwrap();
        let binding_commitment = NonceCommitment::deserialize(
            <[u8; 32]>::from_hex(binding_commitment_input.trim()).unwrap(),
        )?;

        let signer_commitments = SigningCommitments::new(hiding_commitment, binding_commitment); // TODO: Add test for correct error to be returned on failing deserialisation

        commitments.insert(identifier, signer_commitments);
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

pub fn print_values_round_2(signature: SignatureShare, logger: &mut dyn Logger) {
    logger.log("Please send the following to the Coordinator".to_string());
    logger.log(format!(
        "Signature share: {}",
        hex::encode(signature.share().to_bytes())
    ));
    logger.log("=== End of Round 2 ===".to_string());
}
