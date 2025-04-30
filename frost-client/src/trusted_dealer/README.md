# Frost Trusted Dealer Demo

[Overview of demos](https://github.com/ZcashFoundation/frost-zcash-demo/blob/main/README.md)

## Status ⚠

The Trusted Dealer demo is a WIP.

## Usage

NOTE: This is for demo purposes only and should not be used in production.

You will need to have [Rust and Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) installed.

To run:
1. Clone the repo. Run `git clone https://github.com/ZcashFoundation/frost-zcash-demo.git`
2. Run `cargo install`
3. Run `cargo run --bin trusted-dealer`

On startup, the Trusted Dealer demo will prompt for:

1. Minimum number of signers (>= 2) i.e. The threshold number of signers for the secret sharing scheme.

2. Maximum number of signers i.e. the number of shares to generate

```
> cargo run
   Finished dev [unoptimized + debuginfo] target(s) in 0.05s
   Running 'target/debug/frost-trusted-dealer-demo
The minimum number of signers: (2 or more)
2
The maximum number of signers: (must be greater than minimum number of signers)
5
```

The dealer CLI will then use that data to generate:

1. The group public key
2. A commitment to the secret
3. Each signer's public key
4. Each signer's secret share
5. An identifier for each signer

In a "real world" scenario, the secret share should be delivered securely to each participant. For the purposes of the Trusted Dealer demo only, the above data will be output to the terminal. 

In the next round, all signers will receive the data but only the individual signers will receive their personal secret share. 

## Using the output

To generate a key package the participant requires:

* The signer's identifier
* The signer's secret share
* The signer's public key
* The public signing key that represents the entire group

The commitment is used to verify the signer's secret share and to generate the group commitment.

The dealer should use a secure broadcast channel to ensure each participant has a consistent view of this commitment and each participant must [verify the commitments](https://github.com/ZcashFoundation/frost/blob/4055cb9439df2814800c678c8da1760a0f86dc10/frost-core/src/frost/keys.rs#L297). 
The trusted dealer MUST delete the secret_key (used during calculation) and secret_share upon completion.
Use of this method for key generation requires a mutually authenticated secure channel between the dealer and participants to send secret key shares, wherein the channel provides confidentiality and integrity. Mutually authenticated TLS is one possible deployment option.

NOTE: A signer is a participant that generates a signing share which is aggregated with the signing shares of other signers to obtain the final group signature.

## Developer information

### Pre-commit checks

1. Run `cargo make all`

### Coverage

Test coverage checks are performed in the pipeline. This is configured here: `.github/workflows/coverage.yaml`
To run these locally:
1. Install coverage tool by running `cargo install cargo-llvm-cov`
2. Run `cargo cov` (you may be asked if you want to install `llvm-tools-preview`, if so type `Y`)