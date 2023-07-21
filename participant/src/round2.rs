use crate::Logger;
use frost::{
    keys::KeyPackage,
    round1::SigningNonces,
    round2::{self, SignatureShare},
    Error, SigningPackage,
};
use frost_ed25519 as frost;
use std::io::BufRead;

// #[derive(Debug)]
pub struct Round2Config {
    pub signing_package: SigningPackage,
}

// TODO: refactor to generate config
// TODO: handle errors
pub fn round_2_request_inputs(
    input: &mut impl BufRead,
    logger: &mut dyn Logger,
) -> Result<Round2Config, Error> {
    logger.log("=== Round 2 ===".to_string());

    logger.log("Enter the JSON-encoded SigningPackage:".to_string());

    let mut signing_package_json = String::new();

    input.read_line(&mut signing_package_json).unwrap();

    // TODO: change to return a generic Error and use a better error
    let signing_package: SigningPackage = serde_json::from_str(signing_package_json.trim())
        .map_err(|_| Error::MalformedSigningKey)?;

    Ok(Round2Config { signing_package })
}

pub fn generate_signature(
    config: Round2Config,
    key_package: &KeyPackage,
    signing_nonces: &SigningNonces,
) -> Result<SignatureShare, Error> {
    let signing_package = config.signing_package;
    let signature = round2::sign(&signing_package, signing_nonces, key_package)?;
    Ok(signature)
}

pub fn print_values_round_2(signature: SignatureShare, logger: &mut dyn Logger) {
    logger.log("Please send the following to the Coordinator".to_string());
    logger.log(format!(
        "SignatureShare:\n{}",
        serde_json::to_string(&signature).unwrap()
    ));
    logger.log("=== End of Round 2 ===".to_string());
}
