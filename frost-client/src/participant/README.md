# FROST Participant Demo

[Overview of demos](https://github.com/ZcashFoundation/frost-zcash-demo/blob/main/README.md)

## Status ⚠

The Participant Demo is a WIP

## Usage

NOTE: This is for demo purposes only and should not be used in production.

You will need to have [Rust and Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) installed.

To run:
1. Clone the repo. Run `git clone https://github.com/ZcashFoundation/frost-zcash-demo.git`
2. Run `cargo install`
3. Run `cargo run --bin participant`

### Round 1

The participant CLI will prompt for:

1. Your secret share or key package

The participant CLI will then use that data to generate:

1. Signing nonces
2. Signing commitments

### Communication round

The signing commitments will be sent to the coordinator
The coordinator will then send the signing package

### Round 2

The participant CLI will prompt for:

1. Signing package

The participant CLI will then use that data to generate:

1. Signature share

### Communication round

The signature share will be sent to the coordinator
The coordinator will then send the Group signature

## Developer information

### Pre-commit checks

1. Run `cargo make all`

### Coverage

Test coverage checks are performed in the pipeline. This is configured here: `.github/workflows/coverage.yaml`
To run these locally:
1. Install coverage tool by running `cargo install cargo-llvm-cov`
2. Run `cargo make cov` (you may be asked if you want to install `llvm-tools-preview`, if so type `Y`)
