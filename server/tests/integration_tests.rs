use std::{collections::BTreeMap, time::Duration};

use axum_test::TestServer;
use rand::thread_rng;
use server::{args::Args, router};

use reddsa::frost::redpallas as frost;

/// Test the entire FROST signing flow using axum_test.
/// This is a good example of the overall flow but it's not a good example
/// of the client code, see the next test for that.
///
/// Also note that this simulates multiple clients using loops. In practice,
/// each client will run independently.
#[tokio::test]
async fn test_main_router() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();
    let (shares, pubkeys) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
            .unwrap();
    let key_packages: BTreeMap<_, _> = shares
        .iter()
        .map(|(identifier, secret_share)| {
            (
                *identifier,
                frost::keys::KeyPackage::try_from(secret_share.clone()).unwrap(),
            )
        })
        .collect();

    let router = router();
    let server = TestServer::new(router)?;
    let res = server
        .post("/create_new_session")
        .json(&server::CreateNewSessionArgs {
            identifiers: key_packages.keys().copied().collect::<Vec<_>>(),
        })
        .await;
    res.assert_status_ok();
    let r: server::CreateNewSessionOutput = res.json();
    let session_id = r.session_id;

    let mut nonces_map = BTreeMap::<_, _>::new();
    for (identifier, key_package) in key_packages.iter() {
        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);
        nonces_map.insert(*identifier, nonces);
        let res = server
            .post("/send_commitments")
            .json(&server::SendCommitmentsArgs {
                identifier: *identifier,
                session_id,
                commitments,
            })
            .await;
        res.assert_status_ok();
    }

    let res = server
        .post("/get_commitments")
        .json(&server::GetCommitmentsArgs { session_id })
        .await;
    res.assert_status_ok();
    let r: server::GetCommitmentsOutput = res.json();
    let commitments = r.commitments;

    let message = "Hello, world!".as_bytes();
    let signing_package = frost::SigningPackage::new(commitments, message);
    let randomized_params =
        frost::RandomizedParams::new(pubkeys.verifying_key(), &signing_package, &mut rng)?;

    let res = server
        .post("/send_signing_package")
        .json(&server::SendSigningPackageArgs {
            session_id,
            signing_package: signing_package.clone(),
            randomizer: *randomized_params.randomizer(),
        })
        .await;
    res.assert_status_ok();

    for (identifier, key_package) in key_packages.iter() {
        let res = server
            .post("get_signing_package")
            .json(&server::GetSigningPackageArgs { session_id })
            .await;
        res.assert_status_ok();
        let r: server::GetSigningPackageOutput = res.json();

        let signature_share = frost::round2::sign(
            &r.signing_package,
            &nonces_map[identifier],
            key_package,
            r.randomizer,
        )?;

        let res = server
            .post("/send_signature_share")
            .json(&server::SendSignatureShareArgs {
                session_id,
                identifier: *identifier,
                signature_share,
            })
            .await;
        res.assert_status_ok();
    }

    let res = server
        .post("/get_signature_shares")
        .json(&server::GetSignatureSharesArgs { session_id })
        .await;
    res.assert_status_ok();
    let r: server::GetSignatureSharesOutput = res.json();

    let signature = frost::aggregate(
        &signing_package,
        &r.signature_shares,
        &pubkeys,
        &randomized_params,
    )?;

    randomized_params
        .randomized_verifying_key()
        .verify(message, &signature)?;

    let res = server
        .post("/close_session")
        .json(&server::CloseSessionArgs { session_id })
        .await;
    res.assert_status_ok();
    println!("{}", res.text());
    let _: () = res.json();

    Ok(())
}

/// Actually spawn the HTTP server and connect to it using reqwest.
/// A better example on how to write client code.
#[tokio::test]
async fn test_http() -> Result<(), Box<dyn std::error::Error>> {
    // Create test values
    let mut rng = thread_rng();
    let (shares, _pubkeys) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
            .unwrap();
    let key_packages: BTreeMap<_, _> = shares
        .iter()
        .map(|(identifier, secret_share)| {
            (
                *identifier,
                frost::keys::KeyPackage::try_from(secret_share.clone()).unwrap(),
            )
        })
        .collect();

    // Spawn server for testing
    tokio::spawn(async move {
        server::run(&Args {
            ip: "127.0.0.1".to_string(),
            port: 2744,
        })
        .await
        .unwrap();
    });

    // Wait for server to start listening
    // TODO: this could possibly be not enough, use some retry logic instead
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Call create_new_session
    let client = reqwest::Client::new();
    let r = client
        .post("http://127.0.0.1:2744/create_new_session")
        .json(&server::CreateNewSessionArgs {
            identifiers: key_packages.keys().copied().collect::<Vec<_>>(),
        })
        .send()
        .await?
        .json::<server::CreateNewSessionOutput>()
        .await?;
    println!("{}", r.session_id);

    Ok(())
}
