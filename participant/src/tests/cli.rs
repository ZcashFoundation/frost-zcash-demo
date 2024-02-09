use std::io::BufWriter;

use participant::args::Args;
use participant::cli::cli;

// TODO: to restore this test, we need to intercept that generated commitments
// to put them inside the SigningPackage
// #[test]
#[allow(unused)]
async fn check_cli() {
    let args = Args::default();
    let key_package = r#"{"header":{"version":0,"ciphersuite":"FROST-ED25519-SHA512-v1"},"identifier":"0100000000000000000000000000000000000000000000000000000000000000","signing_share":"ee4a66fec3ced53cac04b0abc309bb57f03f8d7dede033e4ae7b6ef57630120f","commitment":["21446705fa7da298998a567a3c2fdd7274903a886dcde9a77f615d915feb6764","56ce223ffbde8ce5971be587cbb0b8b31aa2bc220a6803b9ce73c63f9f432514","6dcc10da9443ef2c9bbd5fc6a9c3bcd4c5ede8048cc0b1342b091fd1ff6dc53c"]}"#;

    let signing_package = r#"{"header":{"version":0,"ciphersuite":"FROST-ED25519-SHA512-v1"},"signing_commitments":{"0100000000000000000000000000000000000000000000000000000000000000":{"header":{"version":0,"ciphersuite":"FROST-ED25519-SHA512-v1"},"hiding":"710a280fcedbcbe626fff055f682e4a525c31f157dd6071ef2c04ea0ecbe8de9","binding":"6dc707cdf26a589b3e2de4f6bae09b94d5d3bb939937b52bc6b16bdecd0b041f"},"0200000000000000000000000000000000000000000000000000000000000000":{"header":{"version":0,"ciphersuite":"FROST-ED25519-SHA512-v1"},"hiding":"777f011bf695e27ce62474747a9c110cc3b827268047913a21030c3eba0e1eed","binding":"67f051035284cd619f0e7fc583eb3cb0c88d993aad621c856edc0f995f4588b2"},"0300000000000000000000000000000000000000000000000000000000000000":{"header":{"version":0,"ciphersuite":"FROST-ED25519-SHA512-v1"},"hiding":"c052599bb7a52911b6b58e7c20747f12d45d23aab4aec98aaecdc7909dc6aff3","binding":"b3fbefc67070b1b56203ef875a2c7caf24802dbc943bdc62decac33287b63b23"}},"message":"74657374"}"#;
    let group_signature = "\"daae8e867c1c3000687a819262099c44e4799853729d87738b4811637a659f3075829c4ee6c5f6767e11b937e18dce20886b0d3f015caaf4ccdb76d4d185910c\"";

    let mut buf = BufWriter::new(Vec::new());

    let input = format!(
        "{}\n{}\n{}\n",
        key_package, signing_package, group_signature
    );

    let signature = cli(&args, &mut input.as_bytes(), &mut buf).await;
    assert!(
        signature.is_ok(),
        "invalid signature: {}",
        signature.unwrap_err()
    );
}
