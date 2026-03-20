use crate::MLDSAAction;

pub(crate) fn mldsa44_cmd(action: &MLDSAAction, output_hex: bool) {
    match action {
        MLDSAAction::Keygen => {
            // let sk = MLDSA44::keygen_sk_only();
            // if output_hex { println!("{:x?}", sk.encode()); } else { println!("{}", sk.encode()); }
        },
        MLDSAAction::KeygenFromSeed => { println!("Generating new private key from seed..."); },
        MLDSAAction::PkFromSk => { println!("Generating new public key from private key..."); },
        MLDSAAction::Sign => { println!("Signing message with private key..."); },
        MLDSAAction::Verify => { println!("Verifying message with public key and signature..."); },
    }
}

fn mldsa_cmd::<MLDSATrait>(action: &MLDSAAction, output_hex: bool)