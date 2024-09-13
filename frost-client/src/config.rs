use core::str;
use std::{
    collections::BTreeMap,
    error::Error,
    fs::File,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
};

use eyre::eyre;
use serde::{Deserialize, Serialize};

use crate::{contact::Contact, write_atomic};

/// The config file, which is serialized with serde.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Config {
    /// The path the config was loaded from.
    #[serde(skip)]
    path: Option<PathBuf>,
    pub version: u8,
    /// The registry of servers the user has registered into, keyed by server
    /// URL.
    #[serde(default)]
    pub registry: BTreeMap<String, Registry>,
    /// The communication key pair for the user.
    pub communication_key: Option<CommunicationKey>,
    /// The address book of the user, keyed by each contact's name.
    #[serde(default)]
    pub contact: BTreeMap<String, Contact>,
    /// The FROST groups the user belongs to, keyed by (TODO)
    #[serde(default)]
    pub group: BTreeMap<String, Group>,
}

/// A registry entry. Note that the server URL is not in the struct;
/// it is the key in the `registry` map in Config.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Registry {
    /// The authentication token, if the user is logged in.
    pub token: Option<String>,
    /// The username of the user
    pub username: String,
}

/// The communication key pair for the user.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommunicationKey {
    /// The private key.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub privkey: Vec<u8>,
    /// The public key.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub pubkey: Vec<u8>,
}

/// A FROST group the user belongs to.
// TODO: add a textual name for the group?
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group {
    /// The encoded public key package for the group.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub public_key_package: Vec<u8>,
    /// The user's encodede key package for the group.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub key_package: Vec<u8>,
    /// The group participants, keyed by (TODO)
    pub participant: BTreeMap<String, Participant>,
}

/// A FROST grou participant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Participant {
    /// The identifier of the participant in the group.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub identifier: Vec<u8>,
    /// The communication public key for the participant.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub pubkey: Vec<u8>,
    /// The server the participant is registered in, if any.
    pub server_url: Option<String>,
    /// The username of the participant in the server, if any.
    pub username: Option<String>,
}

impl Config {
    /// Returns the default path of the config
    /// ($HOME/.config/frost/credentials.toml in Linux) if `path` is None,
    /// otherwise parse the given path and return it.
    pub fn parse_path(path: Option<String>) -> Result<PathBuf, Box<dyn Error>> {
        if let Some(path) = path {
            Ok(PathBuf::from_str(&path)?)
        } else {
            Ok(dirs::config_local_dir()
                .unwrap()
                .join("frost")
                .join("credentials.toml"))
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Read the config from given path, or the default path if None.
    /// If the path does not exist, it will load a default (empty) config.
    /// Calling `write()` later will write to the specified path.
    pub fn read(path: Option<String>) -> Result<Self, Box<dyn Error>> {
        let path = Self::parse_path(path)?;
        if !path.exists() {
            return Ok(Config {
                path: Some(path),
                ..Default::default()
            });
        }
        let bytes = std::fs::read(&path)?;
        let s = str::from_utf8(&bytes)?;
        let mut config: Config = toml::from_str(s)?;
        config.path = Some(path);
        Ok(config)
    }

    /// Write the config to path it was loaded from.
    pub fn write(&self) -> Result<(), Box<dyn Error>> {
        let s = toml::to_string_pretty(self)?;
        let bytes = s.as_bytes();
        Ok(write_atomic::write_file(
            self.path
                .clone()
                .ok_or_else(|| eyre!("path not specified"))?,
            bytes,
        )?)
    }
}
