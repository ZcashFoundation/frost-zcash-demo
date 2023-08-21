# Zcash Foundation FROST Demos

This will be part of a set of demos and a proof of concept application that uses the FROST libraries and reference implementation. The purpose of these demos is to:

1. identify gaps in our documentation
2. provide usage examples for developer facing documentation
3. provide reference implementations for developers wanting to use FROST in a “real world” scenario.

This demo uses the (Ed25519, SHA-512) ciphersuite. The crate can be found [here](https://crates.io/crates/frost-ed25519).

## About FROST (Flexible Round-Optimised Schnorr Threshold signatures)

Unlike signatures in a single-party setting, threshold signatures require cooperation among a threshold number of signers, each holding a share of a common private key. The security of threshold
schemes in general assume that an adversary can corrupt strictly fewer than a threshold number of participants.

[Two-Round Threshold Schnorr Signatures with FROST](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/) presents a variant of a Flexible Round-Optimized Schnorr Threshold (FROST) signature scheme originally defined in [FROST20](https://eprint.iacr.org/2020/852.pdf). FROST reduces network overhead during threshold
signing operations while employing a novel technique to protect against forgery attacks applicable to prior Schnorr-based threshold signature constructions. This variant of FROST requires two rounds to compute a signature, and implements signing efficiency improvements described by [Schnorr21](https://eprint.iacr.org/2021/1375.pdf). Single-round signing with FROST is not implemented here.

## Projects

This repo contains 4 projects:
1. [Trusted Dealer](https://github.com/ZcashFoundation/frost-zcash-demo/tree/main/trusted-dealer)
2. [DKG](https://github.com/ZcashFoundation/frost-zcash-demo/tree/main/dkg)
3. [Coordinator](https://github.com/ZcashFoundation/frost-zcash-demo/tree/main/coordinator)
4. [Participant](https://github.com/ZcashFoundation/frost-zcash-demo/tree/main/participant)

## Status ⚠

Trusted Dealer demo - WIP
DKG demo - WIP
Coordinator demo - WIP
Participant demo - WIP

## Usage

NOTE: This is for demo purposes only and should not be used in production.

You will need to have [Rust and Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) installed.

To run:
1. Clone the repo. Run `git clone https://github.com/ZcashFoundation/frost-zcash-demo.git`
2. Run `cargo install`

and in separate terminals:
3. Run `cargo run --bin trusted-dealer` or `cargo run --bin dkg`
4. Run `cargo run --bin coordinator`
5. Run `cargo run --bin participants`. Do this in separate terminals for separate participants.

## Developer Information

### Pre-commit checks

1. Run `cargo make all`

### Coverage

Test coverage checks are performed in the pipeline. This is configured here: `.github/workflows/coverage.yaml`
To run these locally:
1. Install coverage tool by running `cargo install cargo-llvm-cov`
2. Run `cargo make cov` (you may be asked if you want to install `llvm-tools-preview`, if so type `Y`)
