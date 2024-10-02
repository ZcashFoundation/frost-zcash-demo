use std::error::Error;

use eyre::eyre;

use crate::{
    args::Command,
    config::{CommunicationKey, Config, Registry},
};

pub(crate) async fn init(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Init {
        server_url,
        username,
        config,
    } = (*args).clone()
    else {
        panic!("invalid Command");
    };

    let mut config = Config::read(config)?;

    let pubkey = match &config.communication_key {
        Some(communication_key) => {
            eprintln!("Skipping keypair generation; keypair already generated and stored");
            hex::decode(&communication_key.pubkey)?
        }
        None => {
            eprintln!("Generating keypair... ");
            let builder = snow::Builder::new("Noise_K_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
            let keypair = builder.generate_keypair().unwrap();
            config.communication_key = Some(CommunicationKey {
                privkey: keypair.private.clone(),
                pubkey: keypair.public.clone(),
            });
            keypair.public
        }
    };

    if let (Some(server_url), Some(username)) = (server_url, username) {
        // TODO: check if already registered, prompt to overwrite

        let client = reqwest::Client::new();
        let password = rpassword::prompt_password("Password to use: ").unwrap();
        let rpassword = rpassword::prompt_password("Repeat password: ").unwrap();
        if password != rpassword {
            return Err(eyre!("Passwords are different").into());
        }

        eprintln!("Registering at {}...", server_url);
        let r = client
            .post(format!("http://{}/register", server_url))
            .json(&server::RegisterArgs {
                username: username.clone(),
                password: password.clone(),
                pubkey: pubkey.clone(),
            })
            .send()
            .await?;
        if r.status() != reqwest::StatusCode::OK {
            return Err(eyre!("{}", r.text().await?).into());
        }

        eprintln!("Logging in at {}...", server_url);
        let r = client
            .post(format!("http://{}/login", server_url))
            .json(&server::LoginArgs {
                username: username.clone(),
                password,
            })
            .send()
            .await?;
        if r.status() != reqwest::StatusCode::OK {
            return Err(eyre!("{}", r.text().await?).into());
        }
        let r = r.json::<server::LoginOutput>().await?;

        config.registry.insert(
            server_url,
            Registry {
                token: Some(r.access_token.to_string()),
                username,
            },
        );
    } else {
        eprintln!(
            "Skipping user registration, specify username and server_url if you want to register"
        );
    }

    eprintln!(
        "Writing to config file at {}...",
        config.path().expect("should not be None").display()
    );
    config.write()?;
    eprintln!("Done.");

    Ok(())
}
