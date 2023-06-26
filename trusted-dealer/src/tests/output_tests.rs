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
    let len_test = commitment.len() as u8;
    let mut out = hex::encode([len_test]);
    for c in commitment {
        out = out + &hex::encode(c)
    }
    out
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

    let signer_1_id = "1";
    let signer_2_id = "2";
    let signer_3_id = "3";

    assert_eq!(
        test_logger.0[0],
        format!(
            "Group public key: {}",
            hex::encode(pubkeys.group_public().to_bytes())
        )
    );

    assert_eq!(test_logger.0[1], format!("Participant: {}", signer_1_id));
    assert_eq!(
        test_logger.0[2],
        format!(
            "Secret share: {}",
            hex::encode(shares[&signer_1].value().to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[3],
        format!(
            "Public key: {}",
            hex::encode(pubkeys.signer_pubkeys()[&signer_1].to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[4],
        format!(
            "Commitment: {}",
            encode_commitment_helper(shares[&signer_1].commitment().serialize())
        )
    );

    assert_eq!(test_logger.0[5], format!("Participant: {}", signer_2_id));
    assert_eq!(
        test_logger.0[6],
        format!(
            "Secret share: {}",
            hex::encode(shares[&signer_2].value().to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[7],
        format!(
            "Public key: {}",
            hex::encode(pubkeys.signer_pubkeys()[&signer_2].to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[8],
        format!(
            "Commitment: {}",
            encode_commitment_helper(shares[&signer_2].commitment().serialize())
        )
    );

    assert_eq!(test_logger.0[9], format!("Participant: {}", signer_3_id));
    assert_eq!(
        test_logger.0[10],
        format!(
            "Secret share: {}",
            hex::encode(shares[&signer_3].value().to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[11],
        format!(
            "Public key: {}",
            hex::encode(pubkeys.signer_pubkeys()[&signer_3].to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[12],
        format!(
            "Commitment: {}",
            encode_commitment_helper(shares[&signer_3].commitment().serialize())
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

    let signer_1_id = "1";
    let signer_2_id = "2";
    let signer_3_id = "3";

    assert_eq!(
        test_logger.0[0],
        format!(
            "Group public key: {}",
            hex::encode(pubkeys.group_public().to_bytes())
        )
    );

    assert_eq!(test_logger.0[1], format!("Participant: {}", signer_1_id));
    assert_eq!(
        test_logger.0[2],
        format!(
            "Secret share: {}",
            hex::encode(shares[&signer_1].value().to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[3],
        format!(
            "Public key: {}",
            hex::encode(pubkeys.signer_pubkeys()[&signer_1].to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[4],
        format!(
            "Commitment: {}",
            encode_commitment_helper(shares[&signer_1].commitment().serialize())
        )
    );

    assert_eq!(test_logger.0[5], format!("Participant: {}", signer_2_id));
    assert_eq!(
        test_logger.0[6],
        format!(
            "Secret share: {}",
            hex::encode(shares[&signer_2].value().to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[7],
        format!(
            "Public key: {}",
            hex::encode(pubkeys.signer_pubkeys()[&signer_2].to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[8],
        format!(
            "Commitment: {}",
            encode_commitment_helper(shares[&signer_2].commitment().serialize())
        )
    );

    assert_eq!(test_logger.0[9], format!("Participant: {}", signer_3_id));
    assert_eq!(
        test_logger.0[10],
        format!(
            "Secret share: {}",
            hex::encode(shares[&signer_3].value().to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[11],
        format!(
            "Public key: {}",
            hex::encode(pubkeys.signer_pubkeys()[&signer_3].to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[12],
        format!(
            "Commitment: {}",
            encode_commitment_helper(shares[&signer_3].commitment().serialize())
        )
    );
}

#[test]
fn check_output_with_large_num_of_signers() {
    let mut test_logger = TestLogger(Vec::new());
    let mut rng = thread_rng();
    let config = Config {
        min_signers: 10,
        max_signers: 20,
        secret: Vec::new(),
    };
    let (shares, pubkeys) = trusted_dealer_keygen(&config, &mut rng).unwrap();

    print_values(&shares, &pubkeys, &mut test_logger);

    let signer_10 = Identifier::try_from(10).unwrap();
    let signer_10_id = "10";

    assert_eq!(
        test_logger.0[0],
        format!(
            "Group public key: {}",
            hex::encode(pubkeys.group_public().to_bytes())
        )
    );

    assert_eq!(test_logger.0[37], format!("Participant: {}", signer_10_id));
    assert_eq!(
        test_logger.0[38],
        format!(
            "Secret share: {}",
            hex::encode(shares[&signer_10].value().to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[39],
        format!(
            "Public key: {}",
            hex::encode(pubkeys.signer_pubkeys()[&signer_10].to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[40],
        format!(
            "Commitment: {}",
            encode_commitment_helper(shares[&signer_10].commitment().serialize())
        )
    );
}

#[test]
fn check_output_with_secret_with_large_num_of_signers() {
    let mut test_logger = TestLogger(Vec::new());
    let mut rng = thread_rng();
    let secret: Vec<u8> = vec![
        123, 28, 51, 211, 245, 41, 29, 133, 222, 102, 72, 51, 190, 177, 173, 70, 159, 127, 182, 2,
        90, 14, 199, 139, 58, 121, 12, 110, 19, 169, 131, 4,
    ];
    let config = Config {
        min_signers: 10,
        max_signers: 20,
        secret,
    };
    let (shares, pubkeys) = split_secret(&config, &mut rng).unwrap();

    print_values(&shares, &pubkeys, &mut test_logger);

    let signer_10 = Identifier::try_from(10).unwrap();
    let signer_10_id = "10";

    assert_eq!(
        test_logger.0[0],
        format!(
            "Group public key: {}",
            hex::encode(pubkeys.group_public().to_bytes())
        )
    );

    assert_eq!(test_logger.0[37], format!("Participant: {}", signer_10_id));
    assert_eq!(
        test_logger.0[38],
        format!(
            "Secret share: {}",
            hex::encode(shares[&signer_10].value().to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[39],
        format!(
            "Public key: {}",
            hex::encode(pubkeys.signer_pubkeys()[&signer_10].to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[40],
        format!(
            "Commitment: {}",
            encode_commitment_helper(shares[&signer_10].commitment().serialize())
        )
    );
}
