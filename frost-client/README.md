# frost-client

`frost-client` is a command-line tool that allows running the FROST protocol
using the FROST server to help with communication. It uses a config file to
store things like secret shares, group information and contacts.

Run `frost-client -h` (or `cargo run -p frost-client -- -h`) to get the
command line help.

Eventually, `frost-client` will also be able to be imported as a library to
offer functionality to developers who want to offer similar functionality
to `frost-client` in their own applications (e.g. wallets).
