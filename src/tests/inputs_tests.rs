use crate::inputs::{request_inputs, validate_inputs, Config};

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

#[test]
fn return_config_if_valid_input() {
    let mut valid_input = "3\n6\n".as_bytes();
    let config = request_inputs(&mut valid_input).unwrap();
    let expected = Config {
        min_signers: 3,
        max_signers: 6,
    };

    assert_eq!(expected, config)
}

#[test]
fn return_error_if_invalid_min_signers_input() {
    let mut invalid_input = "hello\n6\n".as_bytes();
    let expected = request_inputs(&mut invalid_input);

    assert_eq!(expected, Err(frost_ed25519::Error::InvalidMinSigners))
}

#[test]
fn return_error_if_invalid_max_signers_input() {
    let mut invalid_input = "4\nworld\n".as_bytes();
    let expected = request_inputs(&mut invalid_input);

    assert_eq!(expected, Err(frost_ed25519::Error::InvalidMaxSigners))
}
