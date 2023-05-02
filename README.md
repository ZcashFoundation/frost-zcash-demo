# Frost Trusted Dealer Demo

A CLI demo for running trusted dealer key generation with the Zcash Foundation's Rust implementation of ['Two-Round Threshold Schnorr Signatures with FROST'](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/).

This will be part of a set of demos and a proof of concept application that uses the FROST libraries and reference implementation. The purpose of this is:

1. To identify gaps in our documentation and provide usage examples for developer facing documentation.
2. To provide reference implementations for developers wanting to use FROST in a “real world” scenario.

This demo uses the (Ed25519, SHA-512) ciphersuite. The crate can be found here: https://crates.io/crates/frost-ed25519

## Status ⚠

The Trusted Dealer demo is a WIP.

## Usage

NOTE: This is for demo purposes only and should not be used in production.

On startup, the Trusted Dealer demo will prompt for:

1. Minimum number of signers (>= 2) i.e. The threshold number of participants for the secret sharing scheme
2. Maximum number of signers i.e. the number of shares to generate

The dealer CLI will then use that data to generate:

1. The group public key
2. A commitment to the secret
3. Each participant’s public key

This above data will be output by the Trusted Dealer demo to the terminal.

# About FROST (Flexible Round-Optimised Schnorr Threshold signatures)

Unlike signatures in a single-party setting, threshold signatures require cooperation among a threshold number of signers, each holding a share of a common private key. The security of threshold
schemes in general assume that an adversary can corrupt strictly fewer than a threshold number of participants.

['Two-Round Threshold Schnorr Signatures with FROST'](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/) presents a variant of a Flexible Round-Optimized Schnorr Threshold (FROST) signature scheme originally defined in [FROST20](https://eprint.iacr.org/2020/852.pdf). FROST reduces network overhead during threshold
signing operations while employing a novel technique to protect against forgery attacks applicable to prior Schnorr-based threshold signature constructions. This variant of FROST requires two rounds to compute a signature, and implements signing efficiency improvements described by [Schnorr21](https://eprint.iacr.org/2021/1375.pdf). Single-round signing with FROST is not implemented here.

## Pre-commit checks

1. Run `cargo make all`

## Coverage

Test coverage checks are performed in the pipeline. This is configured here: `.github/workflows/coverage.yaml`
To run these locally:
1. Install coverage tool by running `cargo install cargo-llvm-cov`
2. Run `cargo cov` (you may be asked if you want to install `llvm-tools-preview`, if so type `Y`)
