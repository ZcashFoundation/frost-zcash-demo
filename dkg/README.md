# FROST DKG Demo

[Overview of demos](https://github.com/ZcashFoundation/frost-zcash-demo/blob/main/README.md)

## Status ⚠

The DKG Demo is a WIP

## Usage

NOTE: This is for demo purposes only and should not be used in production.

You will need to have [Rust and Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) installed.

To run:
1. Clone the repo. Run `git clone https://github.com/ZcashFoundation/frost-zcash-demo.git`
2. Run `cargo install`
3. Run `cargo run --bin dkg`

### Round 1 send package

The DKG demo will prompt for:

1. Minimum number of signers (>= 2) i.e. The threshold number of signers for the secret sharing scheme.
2. Maximum number of signers i.e. the number of shares to generate
3. An identifier

The dkg CLI will then use that data to generate:

1. A round 1 package to send to all other signers

### Round 2 send packages

The DKG demo will prompt for:

1. Identifiers of all signers
2. Their corresponding round 1 package

The dkg CLI will then use that data to generate:

1. A round 2 package to send to other users

### Round 2 receive packages

The DKG demo will prompt for:

1. Identifiers of all signers
2. Their corresponding round 2 package

The dkg CLI will then use that data to generate:

1. A key package
2. A public key package

## Using the output

To generate a key package the participant requires:

* The signer's identifier
* The signer's secret share
* The signer's public key
* The public signing key that represents the entire group

## Developer information

### Pre-commit checks

1. Run `cargo make all`

### Coverage

Test coverage checks are performed in the pipeline. This is configured here: `.github/workflows/coverage.yaml`
To run these locally:
1. Install coverage tool by running `cargo install cargo-llvm-cov`
2. Run `cargo make cov` (you may be asked if you want to install `llvm-tools-preview`, if so type `Y`)
