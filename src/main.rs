use cryptoxide::chacha20::ChaCha20;
use cryptoxide::ed25519;
use cryptoxide::hmac::Hmac;
use cryptoxide::pbkdf2::pbkdf2;
use cryptoxide::sha2::Sha512;

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(required = true)]
    data: String,
    #[clap(required = true)]
    password: String,
}

fn main() {
    let args = Args::parse();

    let xprv = hex::decode(&args.data).expect("valid hexadecimal data");
    if xprv.len() != 128 {
        panic!(
            "xprv is not expected at 128 bytes, but has {} bytes",
            xprv.len()
        )
    }
    let password = args.password.as_bytes();

    let salt = b"encrypted wallet salt";
    let mut out = [0; 40];
    pbkdf2(
        &mut Hmac::new(Sha512::new(), password),
        salt,
        15000,
        &mut out,
    );

    let mut cipher = ChaCha20::new(&out[0..32], &out[32..40]);

    let pk = &xprv[64..96];
    let mut extended_sk = <&[u8; 64]>::try_from(&xprv[0..64]).unwrap().clone();
    cipher.process_mut(&mut extended_sk);

    let p = ed25519::extended_to_public(&extended_sk);
    println!("expect={}", hex::encode(pk));
    println!("found ={}", hex::encode(p));
}
