use frost::Identifier;
use frost_ed25519 as frost;
use rand::thread_rng;

use crate::inputs::Config;
use crate::output::{print_values, Logger};
use crate::trusted_dealer_keygen::{split_secret, trusted_dealer_keygen};

struct TestLogger(Vec<String>);

impl Logger for TestLogger {
    fn log(&mut self, value: String) {
        self.0.push(value);
    }
}

fn encode_commitment_helper(commitment: Vec<[u8; 32]>) -> String {
    let coeff_comm_1 = hex::encode(commitment[0]);
    let coeff_comm_2 = hex::encode(commitment[1]);

    hex::encode("2") + &coeff_comm_1 + &coeff_comm_2
}

#[test]
fn check_output_without_secret() {
    let mut test_logger = TestLogger(Vec::new());
    let mut rng = thread_rng();
    let config = Config {
        min_signers: 2,
        max_signers: 3,
        secret: Vec::new(),
    };
    let (shares, pubkeys) = trusted_dealer_keygen(&config, &mut rng).unwrap();

    print_values(&shares, &pubkeys, &mut test_logger);

    let signer_1 = Identifier::try_from(1).unwrap();
    let signer_2 = Identifier::try_from(2).unwrap();
    let signer_3 = Identifier::try_from(3).unwrap();

    assert_eq!(
        test_logger.0[0],
        format!(
            "Group public key: \"{}\"",
            hex::encode(pubkeys.group_public.to_bytes())
        )
    );

    assert_eq!(test_logger.0[1], format!("Participant {:?}", signer_1));
    assert_eq!(
        test_logger.0[2],
        format!(
            "Secret share: \"{}\"",
            hex::encode(shares[&signer_1].value.to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[3],
        format!(
            "Public key: \"{}\"",
            hex::encode(pubkeys.signer_pubkeys[&signer_1].to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[4],
        format!(
            "Commitment: {}",
            encode_commitment_helper(shares[&signer_1].commitment.serialize())
        )
    );

    assert_eq!(test_logger.0[5], format!("Participant {:?}", signer_2));
    assert_eq!(
        test_logger.0[6],
        format!(
            "Secret share: \"{}\"",
            hex::encode(shares[&signer_2].value.to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[7],
        format!(
            "Public key: \"{}\"",
            hex::encode(pubkeys.signer_pubkeys[&signer_2].to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[8],
        format!(
            "Commitment: {}",
            encode_commitment_helper(shares[&signer_2].commitment.serialize())
        )
    );

    assert_eq!(test_logger.0[9], format!("Participant {:?}", signer_3));
    assert_eq!(
        test_logger.0[10],
        format!(
            "Secret share: \"{}\"",
            hex::encode(shares[&signer_3].value.to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[11],
        format!(
            "Public key: \"{}\"",
            hex::encode(pubkeys.signer_pubkeys[&signer_3].to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[12],
        format!(
            "Commitment: {}",
            encode_commitment_helper(shares[&signer_3].commitment.serialize())
        )
    );
}

#[test]
fn check_output_with_secret() {
    let mut test_logger = TestLogger(Vec::new());
    let mut rng = thread_rng();
    let secret: Vec<u8> = vec![
        123, 28, 51, 211, 245, 41, 29, 133, 222, 102, 72, 51, 190, 177, 173, 70, 159, 127, 182, 2,
        90, 14, 199, 139, 58, 121, 12, 110, 19, 169, 131, 4,
    ];
    let config = Config {
        min_signers: 2,
        max_signers: 3,
        secret,
    };
    let (shares, pubkeys) = split_secret(&config, &mut rng).unwrap();

    print_values(&shares, &pubkeys, &mut test_logger);

    let signer_1 = Identifier::try_from(1).unwrap();
    let signer_2 = Identifier::try_from(2).unwrap();
    let signer_3 = Identifier::try_from(3).unwrap();

    assert_eq!(
        test_logger.0[0],
        format!(
            "Group public key: \"{}\"",
            hex::encode(pubkeys.group_public.to_bytes())
        )
    );

    assert_eq!(test_logger.0[1], format!("Participant {:?}", signer_1));
    assert_eq!(
        test_logger.0[2],
        format!(
            "Secret share: \"{}\"",
            hex::encode(shares[&signer_1].value.to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[3],
        format!(
            "Public key: \"{}\"",
            hex::encode(pubkeys.signer_pubkeys[&signer_1].to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[4],
        format!(
            "Commitment: {}",
            encode_commitment_helper(shares[&signer_1].commitment.serialize())
        )
    );

    assert_eq!(test_logger.0[5], format!("Participant {:?}", signer_2));
    assert_eq!(
        test_logger.0[6],
        format!(
            "Secret share: \"{}\"",
            hex::encode(shares[&signer_2].value.to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[7],
        format!(
            "Public key: \"{}\"",
            hex::encode(pubkeys.signer_pubkeys[&signer_2].to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[8],
        format!(
            "Commitment: {}",
            encode_commitment_helper(shares[&signer_2].commitment.serialize())
        )
    );

    assert_eq!(test_logger.0[9], format!("Participant {:?}", signer_3));
    assert_eq!(
        test_logger.0[10],
        format!(
            "Secret share: \"{}\"",
            hex::encode(shares[&signer_3].value.to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[11],
        format!(
            "Public key: \"{}\"",
            hex::encode(pubkeys.signer_pubkeys[&signer_3].to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[12],
        format!(
            "Commitment: {}",
            encode_commitment_helper(shares[&signer_3].commitment.serialize())
        )
    );
}
