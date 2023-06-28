use frost::{
    keys::{
        KeyPackage, SecretShare, SigningShare, VerifiableSecretSharingCommitment, VerifyingShare,
    },
    round1::{SigningCommitments, SigningNonces},
    Error, Identifier, VerifyingKey,
};
use frost_ed25519 as frost;
use hex::FromHex;
use std::io::BufRead;

// TODO: Rethink the types here. They're inconsistent with each other
#[derive(Debug, PartialEq)]
pub struct Config {
    pub identifier: Identifier,
    pub public_key: VerifyingShare,
    pub group_public_key: VerifyingKey,
    pub signing_share: SigningShare,
    pub vss_commitment: Vec<u8>,
}

pub trait Logger {
    fn log(&mut self, value: String);
}

// TODO: refactor to generate config
pub fn request_inputs(input: &mut impl BufRead, logger: &mut dyn Logger) -> Result<Config, Error> {
    logger.log("Your identifier (this should be an integer between 1 and 65535):".to_string());

    let mut identifier_input = String::new();

    input.read_line(&mut identifier_input).unwrap();

    let identifier = identifier_input
        .trim()
        .parse::<u16>()
        .map_err(|_| Error::MalformedIdentifier)?;

    logger.log("Your public key:".to_string());

    let mut public_key_input = String::new();

    input.read_line(&mut public_key_input).unwrap();

    // A specific VerifyingShare error does not currently exist in Frost so `MalformedVerifyingKey`
    // has been used. This should either be added to Frost or the error handling here can be reconsidered
    let public_key = VerifyingShare::from_bytes(
        <[u8; 32]>::from_hex(public_key_input.trim()).map_err(|_| Error::MalformedVerifyingKey)?,
    )?; //TODO: test error

    logger.log("The group public key:".to_string());
    let mut group_public_key_input = String::new();

    input.read_line(&mut group_public_key_input).unwrap();

    let group_public_key = VerifyingKey::from_bytes(
        <[u8; 32]>::from_hex(group_public_key_input.trim())
            .map_err(|_| Error::MalformedVerifyingKey)?,
    )
    .map_err(|_| Error::MalformedVerifyingKey)?; // TODO: Add test for correct error to be returned on failing deserialisation

    logger.log("Your secret share:".to_string());

    let mut signing_share_input = String::new();

    input.read_line(&mut signing_share_input).unwrap();

    // A specific SigningShare error does not currently exist in Frost so `MalformedSigningKey`
    // has been used. This should either be added to Frost or the error handling here can be reconsidered
    let signing_share = SigningShare::from_bytes(
        <[u8; 32]>::from_hex(signing_share_input.trim()).map_err(|_| Error::MalformedSigningKey)?,
    )?; //TODO: test error

    logger.log("Your verifiable secret sharing commitment:".to_string());

    let mut vss_commitment_input = String::new();

    input.read_line(&mut vss_commitment_input).unwrap();

    let vss_commitment = hex::decode(vss_commitment_input.trim()).unwrap();

    Ok(Config {
        identifier: Identifier::try_from(identifier)?,
        public_key,
        group_public_key,
        signing_share,
        vss_commitment,
    })
}

pub fn generate_key_package(config: &Config) -> Result<KeyPackage, Error> {
    let secret_share = SecretShare::new(
        config.identifier,
        config.signing_share,
        decode_vss_commitment(&config.vss_commitment).unwrap(),
    );
    let key_package = KeyPackage::try_from(secret_share)?;

    Ok(key_package)
}

fn decode_vss_commitment(
    vss_commitment: &Vec<u8>,
) -> Result<VerifiableSecretSharingCommitment, Error> {
    let coeff_commitments_data = vss_commitment[1..vss_commitment.len()].to_vec();

    let n = vss_commitment[0] as usize;
    let l = coeff_commitments_data.len() / n;

    let mut coeff_commitments = Vec::with_capacity(n);

    for i in 0..n {
        let commitment_value = hex::encode(&coeff_commitments_data[(i * l)..((i * l) + l)]);
        let serialized =
            <[u8; 32]>::from_hex(commitment_value).map_err(|_| Error::InvalidCoefficients)?; // TODO: Is this the right error? Need to add test
        coeff_commitments.push(serialized)
    }

    let out = VerifiableSecretSharingCommitment::deserialize(coeff_commitments)?; //TODO: test for this error
    Ok(out)
}

// The nonces are printed out here for demo purposes only. The hiding and binding nonces are SECRET and not to be shared.
pub fn print_values(
    nonces: SigningNonces,
    commitments: SigningCommitments,
    logger: &mut dyn Logger,
) {
    logger.log("=== Round 1 ===".to_string());
    logger.log(format!(
        "Hiding nonce: {}",
        hex::encode(nonces.hiding().to_bytes())
    ));

    logger.log(format!(
        "Binding nonce: {}",
        hex::encode(nonces.binding().to_bytes())
    ));

    logger.log(format!(
        "Hiding commitment: {}",
        hex::encode(commitments.hiding().to_bytes())
    ));

    logger.log(format!(
        "Binding commitment: {}",
        hex::encode(commitments.binding().to_bytes())
    ));
}

#[cfg(test)]
mod tests {
    use frost::keys::VerifiableSecretSharingCommitment;
    use frost_ed25519 as frost;
    use hex::FromHex;

    use crate::decode_vss_commitment;

    // TODO: Add details of encoding
    #[test]
    fn check_decode_vss_commitment() {
        let vss_commitment_input = hex::decode("0353e4f0ed77543d021eb12cac53c35d4d99f5fc0fa5c3dfd82a3e1e296fba01bdcad2a298d93b5f0079f5f3874599ca2295482e9a4fa75be6c6deb273b61ee441e30ae9f78c1b56a4648130417247826afe3499c0d80b449740f8c968c64df0a4").unwrap();
        let expected = VerifiableSecretSharingCommitment::deserialize(vec![
            <[u8; 32]>::from_hex(
                "53e4f0ed77543d021eb12cac53c35d4d99f5fc0fa5c3dfd82a3e1e296fba01bd",
            )
            .unwrap(),
            <[u8; 32]>::from_hex(
                "cad2a298d93b5f0079f5f3874599ca2295482e9a4fa75be6c6deb273b61ee441",
            )
            .unwrap(),
            <[u8; 32]>::from_hex(
                "e30ae9f78c1b56a4648130417247826afe3499c0d80b449740f8c968c64df0a4",
            )
            .unwrap(),
        ])
        .unwrap();

        let actual = decode_vss_commitment(&vss_commitment_input).unwrap();

        assert!(expected == actual);
    }
}
