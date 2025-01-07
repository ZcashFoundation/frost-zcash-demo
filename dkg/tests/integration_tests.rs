use frost_core::{self as frost, Ciphersuite};

use dkg::cli::{cli, MaybeIntoEvenY};

use std::collections::HashMap;
use tokio::io::{AsyncBufRead as BufRead, AsyncBufReadExt as BufReadExt, AsyncWriteExt, BufReader};

use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::Identifier;

// Read a single line from the given reader.
async fn read_line(
    mut reader: (impl BufRead + Send + Sync + Unpin),
) -> Result<String, std::io::Error> {
    let mut s = String::new();
    reader.read_line(&mut s).await.map(|_| s)
}

// Test if the DKG CLI works.
//
// This simulates 3 simultaneous CLIs by using threads.
//
// Since the `pipe` module used for sending and receiving to each thread
// is synchronous, the test is very strict. For example, you won't be able to
// read from a CLI if it's waiting for input, and you can't write to it if it's
// waiting for some output to be read.
//
// If the test gets stuck somewhere, that's likely the reason: you should be
// writing to a CLI instead of reading, or vice-versa. Use `debug` to find
// where in the function it's getting stuck and check if the test at that point
// is correct.
#[tokio::test]
async fn check_dkg() {
    println!("hello world");
    check_dkg_for_ciphersuite::<frost_ed25519::Ed25519Sha512>().await;
    check_dkg_for_ciphersuite::<reddsa::frost::redpallas::PallasBlake2b512>().await;
}

#[allow(clippy::needless_range_loop)]
async fn check_dkg_for_ciphersuite<C: Ciphersuite + 'static + MaybeIntoEvenY>() {
    let mut input_writers = Vec::new();
    let mut output_readers = Vec::new();
    let mut join_handles = Vec::new();

    println!("R");

    for i in 0..3 {
        // Spawn CLIs, one thread per participant

        let (input_reader, input_writer) = tokio::io::simplex(1024 * 1024);
        let mut input_reader = BufReader::new(input_reader);
        let (output_reader, mut output_writer) = tokio::io::simplex(1024 * 1024);
        join_handles.push(tokio::spawn(async move {
            cli::<C>(&mut input_reader, &mut output_writer)
                .await
                .unwrap()
        }));
        input_writers.push(input_writer);
        output_readers.push(BufReader::new(output_reader));

        // Input the config into each CLI
        println!("A");

        assert_eq!(
            read_line(&mut output_readers[i]).await.unwrap(),
            "The minimum number of signers: (2 or more)\n"
        );
        input_writers[i].write_all(b"2\n").await.unwrap();
        println!("B");

        assert_eq!(
            read_line(&mut output_readers[i]).await.unwrap(),
            "The maximum number of signers:\n"
        );
        input_writers[i].write_all(b"3\n").await.unwrap();
        println!("C");

        assert_eq!(
            read_line(&mut output_readers[i]).await.unwrap(),
            "Your identifier (this should be an integer between 1 and 65535):\n"
        );
        input_writers[i]
            .write_all(format!("{}\n", i + 1).as_bytes())
            .await
            .unwrap();
        println!("D");
    }

    let mut round1_packages = HashMap::new();
    for i in 0..3 {
        // Read the Round 1 Packages printed by each participant;
        // put them in a map
        assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");
        assert_eq!(
            read_line(&mut output_readers[i]).await.unwrap(),
            "=== ROUND 1: SEND PACKAGES ===\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");
        assert!(read_line(&mut output_readers[i])
            .await
            .unwrap()
            .starts_with("Round 1 Package to send to all other participants"));
        assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");

        let round1_package_json = read_line(&mut output_readers[i]).await.unwrap();

        assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");

        round1_packages.insert(i, round1_package_json);
    }

    let mut round2_packages = HashMap::new();
    for i in 0..3 {
        // Input the Round 1 Packages from other participants, for each
        // participant i
        assert_eq!(
            read_line(&mut output_readers[i]).await.unwrap(),
            "=== ROUND 1: RECEIVE PACKAGES ===\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");
        assert_eq!(
            read_line(&mut output_readers[i]).await.unwrap(),
            "Input Round 1 Packages from the other 2 participants.\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");
        for j in 0..3 {
            // Input Round 1 Package from participant j
            if i == j {
                continue;
            };
            assert_eq!(
                read_line(&mut output_readers[i]).await.unwrap(),
                "The sender's identifier (hex string):\n"
            );

            // Write j's identifier
            let jid: Identifier<C> = ((j + 1) as u16).try_into().unwrap();
            input_writers[i]
                .write_all(format!("{}\n", hex::encode(jid.serialize())).as_bytes())
                .await
                .unwrap();

            assert_eq!(
                read_line(&mut output_readers[i]).await.unwrap(),
                "Their JSON-encoded Round 1 Package:\n"
            );

            // Write j's package
            input_writers[i]
                .write_all(round1_packages[&j].to_string().as_bytes())
                .await
                .unwrap();

            assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");
        }

        assert_eq!(
            read_line(&mut output_readers[i]).await.unwrap(),
            "=== ROUND 2: SEND PACKAGES ===\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");

        let mut packages = HashMap::new();
        for j in 0..3 {
            // Read Round 2 packages to send to other participants, for
            // each participant
            if i == j {
                continue;
            };
            // Read line indicating who should receive that package;
            // extract hex identifier
            let s = read_line(&mut output_readers[i]).await.unwrap();
            assert!(s.starts_with("Round 2 Package to send to participant"));
            let participant_hex = s.split('\"').collect::<Vec<_>>()[1].to_string();

            assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");

            // Read Round 2 package
            let round2_package_json = read_line(&mut output_readers[i]).await.unwrap();

            assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");

            packages.insert(participant_hex, round2_package_json);
        }
        round2_packages.insert(i, packages);
    }

    let mut public_key_packages = HashMap::new();
    for i in 0..3 {
        // Input Round 2 packages from other participants, for each participant
        assert_eq!(
            read_line(&mut output_readers[i]).await.unwrap(),
            "=== ROUND 2: RECEIVE PACKAGES ===\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");
        assert_eq!(
            read_line(&mut output_readers[i]).await.unwrap(),
            "Input Round 2 Packages from the other 2 participants.\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");
        for j in 0..3 {
            // Input Round 2 Package from participant j
            if i == j {
                continue;
            };
            assert_eq!(
                read_line(&mut output_readers[i]).await.unwrap(),
                "The sender's identifier (hex string):\n"
            );

            // Write j's identifier
            let jid: Identifier<C> = ((j + 1) as u16).try_into().unwrap();
            input_writers[i]
                .write_all(format!("{}\n", hex::encode(jid.serialize())).as_bytes())
                .await
                .unwrap();

            assert_eq!(
                read_line(&mut output_readers[i]).await.unwrap(),
                "Their JSON-encoded Round 2 Package:\n"
            );

            // Write j's package sent to i
            let iid: Identifier<C> = ((i + 1) as u16).try_into().unwrap();
            let iids = hex::encode(iid.serialize());
            let s = round2_packages.get(&j).expect("j").get(&iids).expect("i");
            input_writers[i]
                .write_all(s.to_string().as_bytes())
                .await
                .unwrap();

            assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");
        }

        assert_eq!(
            read_line(&mut output_readers[i]).await.unwrap(),
            "=== DKG FINISHED ===\n"
        );
        assert_eq!(
            read_line(&mut output_readers[i]).await.unwrap(),
            "Participant key package:\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");

        // Read key package
        let key_package_json = read_line(&mut output_readers[i]).await.unwrap();
        let _key_package: KeyPackage<C> = serde_json::from_str(&key_package_json).unwrap();

        assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");
        assert_eq!(
            read_line(&mut output_readers[i]).await.unwrap(),
            "Participant public key package:\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).await.unwrap(), "\n");

        // Read public key package
        let public_key_package_json = read_line(&mut output_readers[i]).await.unwrap();
        let public_key_package: PublicKeyPackage<C> =
            serde_json::from_str(&public_key_package_json).unwrap();
        public_key_packages.insert(i, public_key_package);
    }

    // Check that all public key packages are equal
    assert!(public_key_packages
        .values()
        .all(|p| *p == public_key_packages[&0]));

    // Wait for threads, which should terminate at this point
    for jh in join_handles {
        jh.await.unwrap();
    }
}
