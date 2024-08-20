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
}
