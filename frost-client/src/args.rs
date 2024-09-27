use clap::{Parser, Subcommand};

#[derive(Parser, Clone)]
#[command(version, about, long_about = None)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand, Clone)]
pub(crate) enum Command {
    /// Initializes the user, generating a communication key pair and optionally
    /// registering with a FROST server. The key pair and additional information
    /// are saved to the config file. You can rerun the command to register
    /// in other servers; the communication key pair will not be regenerated.
    Init {
        /// The username to use when registering, if desired.
        #[arg(short, long)]
        username: Option<String>,
        /// The server URL to use, if desired.
        #[arg(short, long)]
        server_url: Option<String>,
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Logs the user on the server and saves the returned authentication token
    /// to the config file.
    Login {
        /// The username to use when logging in.
        #[arg(short, long)]
        username: String,
        /// The server URL to use.
        #[arg(short, long)]
        server_url: String,
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Exports the user's contact, printing a string with the contact
    /// information encoded.
    Export {
        /// The name to use when exporting.
        #[arg(short, long)]
        name: String,
        /// The server URL for which to export a contact. You can use a
        /// substring of the URL.
        #[arg(short, long)]
        server_url: Option<String>,
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Imports a contact into the user's address book, in the config file.
    Import {
        /// The contact exported with `export``
        contact: String,
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Lists the contacts in the user's address book, in the config file.
    Contacts {
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
    },
    TrustedDealer {
        /// The path to the config file to manage.
        ///
        /// You can specify `num_signers` different paths. In that case, the
        /// group information will be added to each config file. This is
        /// particularly useful for tests, where all participants are run in the
        /// same machine with a config file for each.
        ///
        /// If a single path is specified (or none, which will use
        /// $HOME/.local/frost/credentials.toml), then it will run the trusted
        /// dealer process via the FROST server (TODO: this is not supported yet)
        #[arg(short, long)]
        config: Vec<String>,
        /// The name of each participant.
        #[arg(short = 'N', long, value_delimiter = ',')]
        names: Vec<String>,
        #[arg(short = 'C', long, default_value = "ed25519")]
        ciphersuite: String,
        /// The threshold (minimum number of signers).
        #[arg(short = 't', long, default_value_t = 2)]
        threshold: u16,
        /// The total number of participants (maximum number of signers).
        #[arg(short = 'n', long, default_value_t = 3)]
        num_signers: u16,
    },
    /// Lists the groups the user is in.
    Groups {
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
    },
    Coordinator {
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
        /// The server URL to use. You can use a substring of the URL. It will
        /// use the username previously logged in via the `login` subcommand for
        /// the given server.
        #[arg(short, long)]
        server_url: String,
        /// The group to use, identified by the group public key (use `groups`
        /// to list)
        #[arg(short, long)]
        group: String,
        /// The comma-separated usernames of the signers to use.
        #[arg(short = 'S', long, value_delimiter = ',')]
        signers: Vec<String>,
        /// The messages to sign. Each instance can be a file with the raw message,
        /// "" or "-". If "" or "-" is specified, then it will be read from standard
        /// input as a hex string. If none are passed, a single one will be read
        /// from standard input as a hex string.
        #[arg(short = 'm', long)]
        message: Vec<String>,
        /// The randomizers to use. Each instance can be a file with the raw
        /// randomizer, "" or "-". If "" or "-" is specified, then it will be read
        /// from standard input as a hex string. If none are passed, random ones
        /// will be generated. If one or more are passed, the number should match
        /// the `message` parameter.
        #[arg(short = 'r', long)]
        randomizer: Vec<String>,
        /// Where to write the generated raw bytes signature. If "-", the
        /// human-readable hex-string is printed to stdout.
        #[arg(short = 'o', long, default_value = "")]
        signature: String,
    },
}
