use base64::URL_SAFE;
use clap::{App, Arg};
use keri::{
    derivation::{basic::Basic, self_signing::SelfSigning},
    keys::{PrivateKey, PublicKey},
    prefix::{BasicPrefix, Prefix, SelfSigningPrefix},
};
use rand::rngs::OsRng;

fn generate_key_pair() -> (PublicKey, PrivateKey) {
    let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
    let (vk, sk) = (kp.public, kp.secret);
    let vk = PublicKey::new(vk.to_bytes().to_vec());
    let sk = PrivateKey::new(sk.to_bytes().to_vec());
    (vk, sk)
}

fn main() {
    // Parse arguments
    let matches = App::new("SCID")
        .version("1.0")
        .subcommand(App::new("keygen").about("Generate keypair"))
        .subcommand(
            App::new("sign")
                .about("Sign data with given private key")
                .arg(
                    Arg::new("privkey")
                        .short('k')
                        .long("privkey")
                        .takes_value(true)
                        .value_name("KEY")
                        .about("Private key used for signing"),
                )
                .arg(
                    Arg::new("data")
                        .short('d')
                        .long("data")
                        .takes_value(true)
                        .value_name("DATA")
                        .about("Data to sign"),
                ),
        )
        .subcommand(
            App::new("verify")
                .about("Sign data with given private key")
                .arg(
                    Arg::new("pubkey")
                        .short('k')
                        .long("pubkey")
                        .takes_value(true)
                        .value_name("KEY")
                        .about("Public key used for verification"),
                )
                .arg(
                    Arg::new("data")
                        .short('d')
                        .long("data")
                        .takes_value(true)
                        .value_name("DATA")
                        .about("Signed data"),
                )
                .arg(
                    Arg::new("signature")
                        .short('s')
                        .long("signature")
                        .takes_value(true)
                        .value_name("SIGNATURE")
                        .about("Signature"),
                ),
        )
        .get_matches();

    if let Some(ref _matches) = matches.subcommand_matches("keygen") {
        let (pk, sk) = generate_key_pair();
        let bp = Basic::Ed25519.derive(pk);
        let b64_sk = base64::encode_config(sk.key(), URL_SAFE);
        println!("{}", bp.to_str());
        println!("{}", b64_sk);
    }

    if let Some(ref matches) = matches.subcommand_matches("sign") {
        let b64_sk = matches.value_of("privkey").unwrap();
        let sk = PrivateKey::new(base64::decode_config(b64_sk, URL_SAFE).unwrap());
        if let Some(data) = matches.value_of("data") {
            let signature_raw = sk.sign_ed(&data.as_bytes()).unwrap();
            let ssi = SelfSigning::Ed25519Sha512.derive(signature_raw);
            println!("{}", ssi.to_str());
        }
    }

    if let Some(ref matches) = matches.subcommand_matches("verify") {
        let pubkey: BasicPrefix = matches.value_of("pubkey").unwrap().parse().unwrap();
        let signature: SelfSigningPrefix = matches.value_of("signature").unwrap().parse().unwrap();
        let data = matches.value_of("data").unwrap().as_bytes();

        println!("{:?}", pubkey.verify(data, &signature).unwrap())
    }
}
