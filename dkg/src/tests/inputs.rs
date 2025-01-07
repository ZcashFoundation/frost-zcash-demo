use tokio::io::BufWriter;

use crate::inputs::{request_inputs, Config};
use frost::Error;
use frost_ed25519 as frost;

#[tokio::test]
async fn check_valid_input_for_signers() {
    let config = Config::<frost_ed25519::Ed25519Sha512> {
        min_signers: 2,
        max_signers: 3,
        identifier: 1u16.try_into().unwrap(),
    };

    let mut buf = BufWriter::new(Vec::new());
    let mut valid_input = "2\n3\n1\n".as_bytes();
    let expected = request_inputs(&mut valid_input, &mut buf).await.unwrap();

    assert_eq!(expected, config);
}

#[tokio::test]
async fn return_error_if_min_participant_greater_than_max_participant() {
    let mut invalid_input = "4\n3\n1\n".as_bytes();
    let mut buf = BufWriter::new(Vec::new());
    let expected = request_inputs::<frost_ed25519::Ed25519Sha512>(&mut invalid_input, &mut buf)
        .await
        .unwrap_err();

    assert_eq!(
        *expected.downcast::<Error>().unwrap(),
        Error::InvalidMinSigners
    );
}

#[tokio::test]
async fn return_error_if_min_participant_is_less_than_2() {
    let mut invalid_input = "1\n3\n1\n".as_bytes();
    let mut buf = BufWriter::new(Vec::new());
    let expected = request_inputs::<frost_ed25519::Ed25519Sha512>(&mut invalid_input, &mut buf)
        .await
        .unwrap_err();

    assert_eq!(
        *expected.downcast::<Error>().unwrap(),
        Error::InvalidMinSigners
    );
}

#[tokio::test]
async fn return_error_if_max_participant_is_less_than_2() {
    let mut invalid_input = "2\n1\n1\n".as_bytes();
    let mut buf = BufWriter::new(Vec::new());
    let expected = request_inputs::<frost_ed25519::Ed25519Sha512>(&mut invalid_input, &mut buf)
        .await
        .unwrap_err();

    assert_eq!(
        *expected.downcast::<Error>().unwrap(),
        Error::InvalidMaxSigners
    );
}

#[tokio::test]
async fn return_error_if_invalid_min_signers_input() {
    let mut invalid_input = "hello\n6\n1\n".as_bytes();
    let mut buf = BufWriter::new(Vec::new());
    let expected = request_inputs::<frost_ed25519::Ed25519Sha512>(&mut invalid_input, &mut buf)
        .await
        .unwrap_err();

    assert_eq!(
        *expected.downcast::<Error>().unwrap(),
        Error::InvalidMinSigners
    );
}

#[tokio::test]
async fn return_error_if_invalid_max_signers_input() {
    let mut invalid_input = "4\nworld\n1\n".as_bytes();
    let mut buf = BufWriter::new(Vec::new());
    let expected = request_inputs::<frost_ed25519::Ed25519Sha512>(&mut invalid_input, &mut buf)
        .await
        .unwrap_err();

    assert_eq!(
        *expected.downcast::<Error>().unwrap(),
        Error::InvalidMaxSigners
    );
}

#[tokio::test]
async fn return_malformed_identifier_error_if_identifier_invalid() {
    let mut invalid_input = "4\n6\nasecret\n".as_bytes();
    let mut buf = BufWriter::new(Vec::new());
    let expected = request_inputs::<frost_ed25519::Ed25519Sha512>(&mut invalid_input, &mut buf)
        .await
        .unwrap_err();

    assert_eq!(
        *expected.downcast::<Error>().unwrap(),
        Error::MalformedIdentifier
    );
}
