# FROST Server

This is a JSON-HTTPS server that allow FROST clients (Coordinator and
Participants) to run FROST without needing to directly connect to one another.


## Status ⚠

This project has not being audited.


## Usage

NOTE: This is for demo purposes only and should not be used in production.

You will need to have [Rust and Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) installed.

To compile and run:

1. Clone the repo. Run `git clone https://github.com/ZcashFoundation/frost-zcash-demo.git`
2. Run `cargo build --release --bin frostd`
3. Run `./target/release/frostd -h` to learn about the command line arguments.

You will need to specify a TLS certificate and key with the `--tls-cert`
and `--tls-key` arguments.

For more details on using and deploying, refer to the [ZF FROST
Book](https://frost.zfnd.org/).
