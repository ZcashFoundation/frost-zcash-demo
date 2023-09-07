#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas::keys::PositiveY;

use frost::keys::{PublicKeyPackage, SecretShare};
use frost::Identifier;
use itertools::Itertools;
use std::collections::HashMap;
use std::io::Write;

fn get_identifier_value(i: Identifier) -> String {
    let s = i.serialize();
    let le_bytes: [u8; 2] = [s[0], s[1]];
    u16::from_le_bytes(le_bytes).to_string()
}

pub fn print_values(
    keys: &HashMap<Identifier, SecretShare>,
    pubkeys: &PublicKeyPackage,
    logger: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "redpallas")]
    let pubkeys = pubkeys.clone().into_positive_y();
    #[cfg(feature = "redpallas")]
    let pubkeys = &pubkeys;

    writeln!(
        logger,
        "Public key package:\n{}",
        serde_json::to_string(pubkeys).unwrap()
    )?;

    for (k, v) in keys.iter().sorted_by_key(|x| x.0) {
        writeln!(logger, "Participant: {}", get_identifier_value(*k))?;
        writeln!(
            logger,
            "Secret share:\n{}",
            serde_json::to_string(v).unwrap()
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::output::get_identifier_value;
    use frost::Identifier;
    use frost_ed25519 as frost;

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
