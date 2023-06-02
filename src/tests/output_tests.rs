use frost::Identifier;
use frost_ed25519 as frost;
use rand::thread_rng;

use crate::inputs::Config;
use crate::output::{print_values, Logger};
use crate::trusted_dealer_keygen::trusted_dealer_keygen;

struct TestLogger(Vec<String>);

impl Logger for TestLogger {
    fn log(&mut self, value: String) {
        self.0.push(value);
    }
}

#[test]
fn check_output() {
    let mut test_logger = TestLogger(Vec::new());
    let mut rng = thread_rng();
    let config = Config {
        min_signers: 2,
        max_signers: 3,
        secret: Vec::new(),
    };
    let (key_packages, pubkeys) = trusted_dealer_keygen(&config, &mut rng).unwrap();

    print_values(&key_packages, pubkeys, &mut test_logger);

    let signer_1 = Identifier::try_from(1).unwrap();
    let signer_2 = Identifier::try_from(2).unwrap();
    let signer_3 = Identifier::try_from(3).unwrap();

    assert_eq!(
        test_logger.0[0],
        format!(
            "Group public key: \"{}\"",
            hex::encode(key_packages[&signer_1].group_public.to_bytes())
        )
    );

    assert_eq!(test_logger.0[1], format!("Participant {:?}", signer_1));
    assert_eq!(
        test_logger.0[2],
        format!(
            "Secret share: \"{}\"",
            hex::encode(key_packages[&signer_1].secret_share.to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[3],
        format!(
            "Public key: \"{}\"",
            hex::encode(key_packages[&signer_1].public.to_bytes())
        )
    );

    assert_eq!(test_logger.0[4], format!("Participant {:?}", signer_2));
    assert_eq!(
        test_logger.0[5],
        format!(
            "Secret share: \"{}\"",
            hex::encode(key_packages[&signer_2].secret_share.to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[6],
        format!(
            "Public key: \"{}\"",
            hex::encode(key_packages[&signer_2].public.to_bytes())
        )
    );

    assert_eq!(test_logger.0[7], format!("Participant {:?}", signer_3));
    assert_eq!(
        test_logger.0[8],
        format!(
            "Secret share: \"{}\"",
            hex::encode(key_packages[&signer_3].secret_share.to_bytes())
        )
    );
    assert_eq!(
        test_logger.0[9],
        format!(
            "Public key: \"{}\"",
            hex::encode(key_packages[&signer_3].public.to_bytes())
        )
    );
}
