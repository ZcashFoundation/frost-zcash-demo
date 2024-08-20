use std::error::Error;

use eyre::eyre;

use crate::{
    args::Command,
    config::{Config, Registry},
};

pub(crate) async fn login(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Login {
        server_url,
        username,
        config,
    } = (*args).clone()
    else {
        panic!("invalid Command");
    };

    let mut config = Config::read(config)?;

    let client = reqwest::Client::new();
    let password = rpassword::prompt_password("Password: ").unwrap();

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

    eprintln!(
        "Writing to config file at {}...",
        config.path().expect("should not be None").display()
    );
    config.write()?;
    eprintln!("Done.");

    Ok(())
}
