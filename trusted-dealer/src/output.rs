use frost::keys::{PublicKeyPackage, SecretShare, VerifiableSecretSharingCommitment};
use frost::Identifier;
use frost_ed25519 as frost;
use itertools::Itertools;
use std::collections::HashMap;

pub trait Logger {
    fn log(&mut self, value: String);
}

fn encode_commitment(vss_commitment: &VerifiableSecretSharingCommitment) -> String {
    let serialized = vss_commitment.serialize();
    let num = serialized.len();

    let mut out = hex::encode([num as u8]);
    for cc in serialized {
        out = out + &hex::encode(cc)
    }
    out
}

fn get_identifier_value(i: Identifier) -> String {
    let s = i.serialize();
    let le_bytes: [u8; 2] = [s[0], s[1]];
    u16::from_le_bytes(le_bytes).to_string()
}

pub fn print_values(
    keys: &HashMap<Identifier, SecretShare>,
    pubkeys: &PublicKeyPackage,
    logger: &mut dyn Logger,
) {
    logger.log(format!(
        "Group public key: {}",
        hex::encode(pubkeys.group_public().serialize())
    ));

    println!("---");

    for (k, v) in keys.iter().sorted_by_key(|x| x.0) {
        logger.log(format!("Participant: {}", get_identifier_value(*k)));
        logger.log(format!(
            "Secret share: {}",
            hex::encode(v.value().serialize())
        ));
        logger.log(format!(
            "Public key: {}",
            hex::encode(pubkeys.signer_pubkeys()[k].serialize())
        ));
        logger.log(format!(
            "Your verifiable secret sharing commitment: {}",
            encode_commitment(v.commitment())
        ));
        println!("---")
    }
}

#[cfg(test)]
mod tests {
    use crate::output::{encode_commitment, get_identifier_value};
    use frost::{keys::VerifiableSecretSharingCommitment, Identifier};
    use frost_ed25519 as frost;
    use hex::FromHex;

    #[test]
    fn check_encode_commitment() {
        let coeff_comm_1 = "538d43e67bc9c22a3befdf24e68f29bfc9bcbd844736e5b82fdab1545bceddcf";
        let coeff_comm_2 = "6bc2053a2bedc6a071c74495965c960a6d2655720edba2a5aa68b8e160c9f55d";
        let coeff_comm_3 = "eb73cfae619afa59984754e5f3e93ba2357164ce113b09e542365d8313d6f091";

        let expected = "03".to_string() + coeff_comm_1 + coeff_comm_2 + coeff_comm_3;

        let decoded_1 = <[u8; 32]>::from_hex(coeff_comm_1).unwrap();
        let decoded_2 = <[u8; 32]>::from_hex(coeff_comm_2).unwrap();
        let decoded_3 = <[u8; 32]>::from_hex(coeff_comm_3).unwrap();

        let vss_commitment =
            VerifiableSecretSharingCommitment::deserialize(vec![decoded_1, decoded_2, decoded_3])
                .unwrap();
        let commitment = encode_commitment(&vss_commitment);
        assert!(commitment == expected)
    }

    #[test]
    fn check_get_identifier_value() {
        let min = "1";
        let identifier_min = Identifier::try_from(1).unwrap();

        assert!(get_identifier_value(identifier_min) == min);

        let max = "65535";
        let identifier_max = Identifier::try_from(65535).unwrap();

        assert!(get_identifier_value(identifier_max) == max);
    }
}
