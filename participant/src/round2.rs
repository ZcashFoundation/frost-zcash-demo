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

    logger.log("Enter the message to sign (received from the coordinator):".to_string());

    let mut message_input = String::new();

    input.read_line(&mut message_input).unwrap();

    let message = hex::decode(message_input.trim()).unwrap();

    let mut commitments = vec![signing_commitments];

    for _ in 2..=signers {
        logger.log("Identifier:".to_string());

        let mut identifier_input = String::new();

        input.read_line(&mut identifier_input).unwrap();

        let id_value = identifier_input.trim().parse::<u16>().unwrap();
        let identifier = Identifier::try_from(id_value).unwrap();

        logger.log(format!("Hiding commitment {}:", id_value));
        let mut hiding_commitment_input = String::new();

        input.read_line(&mut hiding_commitment_input).unwrap();
        let hiding_commitment = NonceCommitment::from_bytes(
            <[u8; 32]>::from_hex(hiding_commitment_input.trim()).unwrap(),
        )?;

        logger.log(format!("Binding commitment {}:", id_value));
        let mut binding_commitment_input = String::new();

        input.read_line(&mut binding_commitment_input).unwrap();
        let binding_commitment = NonceCommitment::from_bytes(
            <[u8; 32]>::from_hex(binding_commitment_input.trim()).unwrap(),
        )?;

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

fn encode_signature_response(signature_share: SignatureShare) -> String {
    let id = hex::encode(signature_share.identifier().serialize());
    let sig = hex::encode(signature_share.signature().to_bytes());
    id + &sig
}

pub fn print_values_round_2(signature: SignatureShare, logger: &mut dyn Logger) {
    logger.log("Please send the following to the Coordinator".to_string());
    logger.log(format!(
        "Signature share: {}",
        encode_signature_response(signature)
    ));
    logger.log("=== End of Round 2 ===".to_string());
}

#[cfg(test)]
mod tests {
    use frost::{
        round2::{SignatureResponse, SignatureShare},
        Identifier,
    };
    use frost_ed25519 as frost;
    use hex::FromHex;

    use crate::round2::encode_signature_response;

    // TODO: Add details of encoding
    #[test]
    fn check_encode_signature_response() {
        const SIGNATURE_RESPONSE: &str =
            "44055c54d0604cbd006f0d1713a22474d7735c5e8816b1878f62ca94bf105900";
        let signature_response =
            SignatureResponse::from_bytes(<[u8; 32]>::from_hex(SIGNATURE_RESPONSE).unwrap())
                .unwrap();
        let signature_share =
            SignatureShare::new(Identifier::try_from(1).unwrap(), signature_response);

        let expected = "010000000000000000000000000000000000000000000000000000000000000044055c54d0604cbd006f0d1713a22474d7735c5e8816b1878f62ca94bf105900";
        let signature = encode_signature_response(signature_share);

        assert!(expected == signature)
    }
}
