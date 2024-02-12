# FROST Server


This is a HTTP server that allow clients (Coordinator and Participants) to
run FROST without needing to directly connect to one another.


## Status ⚠

This is a prototype which is NOT SECURE since messages are not encrypted nor
authenticated. DO NOT USE this for anything other than testing.


## Usage

NOTE: This is for demo purposes only and should not be used in production.

You will need to have [Rust and Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) installed.

To run:
1. Clone the repo. Run `git clone https://github.com/ZcashFoundation/frost-zcash-demo.git`
2. Run `cargo install`
3. Run `cargo run --bin server`

You can specify the IP and port to bind to using `--ip` and `--port`, e.g.
`cargo run --bin server -- --ip 127.0.0.1 --port 2744`.

## TODO

- Add specific error codes
- Remove frost-specific types (when data is encrypted)
- Session timeouts
- Encryption/authentication
- DoS protections and other production-ready requirements
-