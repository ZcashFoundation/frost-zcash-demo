use crate::inputs::{validate_inputs, Config};

#[test]
fn check_valid_input_for_signers() {
    let config = Config {
        min_signers: 2,
        max_signers: 3,
    };

    let expected = validate_inputs(&config);

    assert_eq!(expected, Ok(()));
}

#[test]
fn return_error_if_min_participant_greater_than_max_participant() {
    let config = Config {
        min_signers: 4,
        max_signers: 3,
    };

    let expected = validate_inputs(&config);

    assert_eq!(expected, Err(frost_ed25519::Error::InvalidMinSigners));
}

#[test]
fn return_error_if_min_participant_is_less_than_2() {
    let config = Config {
        min_signers: 1,
        max_signers: 3,
    };

    let expected = validate_inputs(&config);

    assert_eq!(expected, Err(frost_ed25519::Error::InvalidMinSigners));
}

#[test]
fn return_error_if_max_participant_is_less_than_2() {
    let config = Config {
        min_signers: 2,
        max_signers: 1,
    };

    let expected = validate_inputs(&config);

    assert_eq!(expected, Err(frost_ed25519::Error::InvalidMaxSigners));
}
