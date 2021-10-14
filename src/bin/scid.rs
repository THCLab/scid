use std::{
    convert::TryInto,
    fs::{self},
    io::{self, Read},
    sync::Arc,
};

use base64::URL_SAFE;
use clap::{App, Arg};
use keri::{
    database::sled::SledEventDatabase,
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    event_message::{
        event_msg_builder::{EventMsgBuilder, EventType},
        parse::{signed_event_stream, signed_message},
    },
    keys::{PrivateKey, PublicKey},
    prefix::{AttachedSignaturePrefix, BasicPrefix, Prefix, SelfSigningPrefix},
    processor::EventProcessor,
    state::IdentifierState,
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
        .subcommand(
            App::new("gen")
                .about("Generate keypair and kel")
                .arg(
                    Arg::new("key-output")
                        .long("ko")
                        .takes_value(true)
                        .value_name("FILE")
                        .about("Set output file for keys"),
                )
                .arg(
                    Arg::new("next-output")
                        .long("no")
                        .takes_value(true)
                        .value_name("FILE")
                        .about("Set output file for next keys"),
                )
                .arg(
                    Arg::new("kel-output")
                        .short('o')
                        .takes_value(true)
                        .value_name("FILE")
                        .about("Set output file for kel"),
                ),
        )
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
        .subcommand(
            App::new("rot")
                .about("Rotate keys and make rotation event")
                .arg(
                    Arg::new("next-privkey")
                        .long("sk")
                        .takes_value(true)
                        .value_name("KEY")
                        .about("Next private key"),
                )
                .arg(
                    Arg::new("next-pubkey")
                        .long("pk")
                        .takes_value(true)
                        .value_name("KEY")
                        .about("Next public key"),
                )
                .arg(
                    Arg::new("next-output")
                        .long("no")
                        .takes_value(true)
                        .value_name("FILE")
                        .about("Set output file for next keys"),
                )
                .arg(
                    Arg::new("kel-output")
                        .short('o')
                        .takes_value(true)
                        .value_name("FILE")
                        .about("Set output file for kel"),
                ),
        )
        .get_matches();

    if let Some(ref matches) = matches.subcommand_matches("gen") {
        let (pk, sk) = generate_key_pair();
        let bp = Basic::Ed25519.derive(pk);
        let b64_sk = base64::encode_config(sk.key(), URL_SAFE);
        let (npk, nsk) = generate_key_pair();
        let nbp = Basic::Ed25519.derive(npk);
        let nb64_sk = base64::encode_config(nsk.key(), URL_SAFE);
        if let Some(path) = matches.value_of("key-output") {
            let keys_str = [bp.to_str(), b64_sk].join("\n");
            fs::write(path, keys_str).expect("Unable to write file")
        }
        if let Some(path) = matches.value_of("next-output") {
            let keys_str = [nbp.to_str(), nb64_sk].join("\n");
            fs::write(path, keys_str).expect("Unable to write file")
        }

        let icp = EventMsgBuilder::new(EventType::Inception)?
            .with_keys(vec![bp])
            .with_next_keys(vec![nbp])
            .build()?;

        let signature = sk.sign_ed(&icp.serialize().unwrap()).unwrap();
        let att = AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, signature, 0);

        let signed_icp = icp.sign("-A".try_into().unwrap(), vec![att]);
        // just to check if event is correct
        let _s = signed_message(&signed_icp.serialize().unwrap()).unwrap().1;

        if let Some(path) = matches.value_of("kel-output") {
            let kel_str = String::from_utf8(signed_icp.serialize().unwrap()).unwrap();
            fs::write(path, kel_str).expect("Unable to write file")
        }

        println!("{}", icp.event.prefix.to_str());
    }

    if let Some(ref matches) = matches.subcommand_matches("rot") {
        let mut serialized_kel = String::new();
        let mut stdin = io::stdin();
        stdin.read_to_string(&mut serialized_kel).unwrap();

        use tempfile::Builder;

        // Create test db and event processor.
        let db_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = db_root.path();

        let db = SledEventDatabase::new(path)?;
        let proc = EventProcessor::new(Arc::new(db));
        let s = signed_event_stream(serialized_kel.as_bytes()).unwrap().1;
        let states: Vec<Option<IdentifierState>> =
            s.into_iter().map(|p| proc.process(p).unwrap()).collect();
        let state = states.last().unwrap().as_ref().unwrap();

        let (npk, nsk) = generate_key_pair();
        let nbp = Basic::Ed25519.derive(npk);
        let nb64_sk = base64::encode_config(nsk.key(), URL_SAFE);

        if let Some(path) = matches.value_of("next-output") {
            let keys_str = [nbp.to_str(), nb64_sk].join("\n");
            fs::write(path, keys_str).expect("Unable to write file")
        }

        let pub_key: BasicPrefix = if let Some(bp) = matches.value_of("next-pubkey") {
            Ok(bp.parse()?)
        } else {
            Err(Error::AppError("missing public key arg".into()))
        }?;

        let rot = EventMsgBuilder::new(EventType::Rotation)?
            .with_prefix(state.prefix.clone())
            .with_sn(state.sn + 1)
            .with_previous_event(SelfAddressing::Blake3_256.derive(&state.last))
            .with_keys(vec![pub_key])
            .with_next_keys(vec![nbp])
            .build()?;

        let priv_key = if let Some(b64key) = matches.value_of("next-privkey") {
            PrivateKey::new(base64::decode_config(b64key, URL_SAFE).unwrap())
        } else {
            PrivateKey::new(vec![])
        };

        let signature = priv_key.sign_ed(&rot.serialize().unwrap()).unwrap();
        let att = AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, signature, 0);

        let signed_rot = rot
            .sign("-A".try_into().unwrap(), vec![att])
            .serialize()
            .unwrap();
        // just to check if event is correct
        let s = signed_message(&signed_rot).unwrap().1;
        proc.process(s).unwrap();

        if let Some(path) = matches.value_of("kel-output") {
            let kel_str = proc.get_kerl(&state.prefix).unwrap().unwrap();
            fs::write(path, kel_str).expect("Unable to write file")
        }
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
        let signature: SelfSigningPrefix = matches
            .value_of("signature")
            .ok_or(Error::AppError("Missing signature argument".into()))?
            .parse()?;
        let data = matches
            .value_of("data")
            .ok_or(Error::AppError("Missing data argument".into()))?
            .as_bytes();

        println!("{:?}", pubkey.verify(data, &signature)?);
    };

    Ok(())
}
