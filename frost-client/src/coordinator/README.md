# FROST Coordinator Demo

[Overview of demos](https://github.com/ZcashFoundation/frost-zcash-demo/blob/main/README.md)

## Status ⚠

The Coordinator Demo is a WIP

## Usage

NOTE: This is for demo purposes only and should not be used in production.

You will need to have [Rust and Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) installed.

To run:
1. Clone the repo. Run `git clone https://github.com/ZcashFoundation/frost-zcash-demo.git`
2. Run `cargo install`
3. Run `cargo run --bin coordinator`

### Step 1

The coordinator CLI will prompt for:

1. The public key package
2. The number of signers participating and their corresponding identifiers

### Communication round

Each participant will send their commitments

### Step 2

The coordinator CLI will prompt for:

1. A message
2. The commitments for each participant

The coordinator CLI will then use that data to generate:

1. Signing package

### Communication round

The signing package will be sent to all participants
The coordinator will receive each participant's signature shares

### Step 3

The coordinator CLI will prompt for:

1. Signature shares for ecah participant

The coordinator CLI will then use that data to generate:

1. The group signature

### Communication round

The group signature will then be sent to all participants

## Developer information

### Pre-commit checks

1. Run `cargo make all`

### Coverage

Test coverage checks are performed in the pipeline. This is configured here: `.github/workflows/coverage.yaml`
To run these locally:
1. Install coverage tool by running `cargo install cargo-llvm-cov`
2. Run `cargo make cov` (you may be asked if you want to install `llvm-tools-preview`, if so type `Y`)
