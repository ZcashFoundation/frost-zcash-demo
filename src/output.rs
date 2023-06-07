use std::collections::HashMap;

use frost_ed25519 as frost;

use frost::keys::{PublicKeyPackage, SecretShare, VerifiableSecretSharingCommitment};
use frost::Identifier;

use itertools::Itertools;

pub trait Logger {
    fn log(&mut self, value: String);
}

fn encode_commitment(vss_commitment: VerifiableSecretSharingCommitment) -> String {
    let serialized = vss_commitment.serialize();
    let num = serialized.len().to_string();

    let mut out = hex::encode(num);
    for cc in serialized {
        out = out + &hex::encode(cc)
    }
    out
}

pub fn print_values(
    keys: &HashMap<Identifier, SecretShare>,
    pubkeys: &PublicKeyPackage,
    logger: &mut dyn Logger,
) {
    logger.log(format!(
        "Group public key: {:x?}",
        hex::encode(pubkeys.group_public.to_bytes())
    ));

    println!("---");

    for (k, v) in keys.iter().sorted_by_key(|x| x.0) {
        logger.log(format!("Participant {:?}", k));
        logger.log(format!(
            "Secret share: {:?}",
            hex::encode(v.value.to_bytes())
        ));
        logger.log(format!(
            "Public key: {:?}",
            hex::encode(pubkeys.signer_pubkeys[k].to_bytes())
        ));
        logger.log(format!(
            "Commitment: {}",
            encode_commitment(v.commitment.clone())
        ));
        println!("---")
    }
}

#[cfg(test)]
mod tests {
    use hex::FromHex;

    use frost_ed25519 as frost;

    use frost::keys::VerifiableSecretSharingCommitment;

    use crate::output::encode_commitment;

    #[test]
    fn check_encode_commitment() {
        let coeff_comm_1 = "538d43e67bc9c22a3befdf24e68f29bfc9bcbd844736e5b82fdab1545bceddcf";
        let coeff_comm_2 = "6bc2053a2bedc6a071c74495965c960a6d2655720edba2a5aa68b8e160c9f55d";
        let coeff_comm_3 = "eb73cfae619afa59984754e5f3e93ba2357164ce113b09e542365d8313d6f091";

        let expected = hex::encode("3") + coeff_comm_1 + coeff_comm_2 + coeff_comm_3;

        let decoded_1 = <[u8; 32]>::from_hex(coeff_comm_1).unwrap();
        let decoded_2 = <[u8; 32]>::from_hex(coeff_comm_2).unwrap();
        let decoded_3 = <[u8; 32]>::from_hex(coeff_comm_3).unwrap();

        let vss_commitment =
            VerifiableSecretSharingCommitment::deserialize(vec![decoded_1, decoded_2, decoded_3])
                .unwrap();
        let commitment = encode_commitment(vss_commitment);
        assert!(commitment == expected)
    }
}
