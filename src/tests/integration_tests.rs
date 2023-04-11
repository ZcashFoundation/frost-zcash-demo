use crate::{inputs::Config, keygen};

#[test]
fn check_keygen() {
    let config = Config {
        min_signers: 2,
        max_signers: 3,
    };

    let keygen = keygen(config);

    assert!(keygen.is_ok());
}
