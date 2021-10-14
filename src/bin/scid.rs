use std::{fs::{self, File}, io::Write};

use base64::URL_SAFE;
use clap::{App, Arg};
use keri::{
    derivation::{basic::Basic, self_signing::SelfSigning},
    keys::{PrivateKey, PublicKey},
    prefix::{BasicPrefix, Prefix, SelfSigningPrefix},
};
use rand::rngs::OsRng;
use scid::error::Error;

fn generate_key_pair() -> (PublicKey, PrivateKey) {
    let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
    let (vk, sk) = (kp.public, kp.secret);
    let vk = PublicKey::new(vk.to_bytes().to_vec());
    let sk = PrivateKey::new(sk.to_bytes().to_vec());
    (vk, sk)
}

fn main() -> Result<(), Error> {
    // Parse arguments
    let matches = App::new("SCID")
        .version("1.0")
        .subcommand(App::new("gen")
            .arg(
                    Arg::new("key-output")
                        .long("ko")
                        .takes_value(true)
                        .value_name("FILE")
                        .about("Set output file for keys"),
                )
            .about("Generate keypair"))
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
                .about("Verify signature with given public key")
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

    if let Some(ref matches) = matches.subcommand_matches("gen") {
        
        let (pk, sk) = generate_key_pair();
        let bp = Basic::Ed25519.derive(pk);
        let b64_sk = base64::encode_config(sk.key(), URL_SAFE);
        if let Some(path) = matches.value_of("key-output") {
            let keys_str = [bp.to_str(), b64_sk].join("\n");
            fs::write(path, keys_str).expect("Unable to write file")
        }
        println!("{}", bp.to_str());
    }

    if let Some(ref matches) = matches.subcommand_matches("sign") {
        let b64_sk = matches
            .value_of("privkey")
            .ok_or(Error::AppError("Missing private key argument".into()))?;
        let sk = PrivateKey::new(base64::decode_config(b64_sk, URL_SAFE)?);
        if let Some(data) = matches.value_of("data") {
            let signature_raw = sk.sign_ed(&data.as_bytes())?;
            let ssi = SelfSigning::Ed25519Sha512.derive(signature_raw);
            println!("{}", ssi.to_str());
        }
    }

    if let Some(ref matches) = matches.subcommand_matches("verify") {
        let pubkey: BasicPrefix = matches
            .value_of("pubkey")
            .ok_or(Error::AppError("Missing public key argument".into()))?
            .parse()?;
        let signature: SelfSigningPrefix = matches.value_of("signature").ok_or(Error::AppError("Missing signature argument".into()))?.parse()?;
        let data = matches
            .value_of("data")
            .ok_or(Error::AppError("Missing data argument".into()))?
            .as_bytes();

        println!("{:?}", pubkey.verify(data, &signature)?);
    };

    Ok(())
}
