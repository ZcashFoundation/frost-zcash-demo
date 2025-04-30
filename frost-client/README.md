# frost-client

`frost-client` is a command-line tool that allows running the FROST protocol
using the FROST server to help with communication. It uses a config file to
store things like secret shares, group information and contacts.

Run `frost-client -h` (or `cargo run -p frost-client -- -h`) to get the
command line help.

Eventually, `frost-client` will also be able to be imported as a library to
offer functionality to developers who want to offer similar functionality
to `frost-client` in their own applications (e.g. wallets).


## Documentation

For an usage example, check https://frost.zfnd.org/zcash/ywallet-demo.html


## Status

This tool has been audited: https://leastauthority.com/blog/audits/zcash-frost-demo/

However, be advised that it stores secrets unencrypted in the config file. We
recommend people building their own tools using frost-client as a base; but if
you want to use frost-client directly, make sure to take steps to protect the
config file.


## Other binaries (dkg, trusted-dealer, coordinator, participants)

This package contains additional binaries. These were earlier versions of this
tool and provided a lower-level interface where all the inputs are provided in
the command line or via stdin. They should be still functional but won't be
actively tested and maintained in the future.