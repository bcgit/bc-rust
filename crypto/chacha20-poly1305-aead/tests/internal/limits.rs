use super::*;

fn state() -> State {
    let key = KeyMaterial::from_bytes_as_type(&[7; 32], KeyType::SymmetricCipherKey).unwrap();
    State::new(&key, &[9; 12]).unwrap()
}

fn near_limit() -> State {
    let key = KeyMaterial::from_bytes_as_type(&[7; 32], KeyType::SymmetricCipherKey).unwrap();
    let mut state = state();
    assert_eq!(state.cipher.remaining_bytes(), MAX_MESSAGE_LEN);
    state.cipher = ChaCha20::new(&key, &[9; 12], u32::MAX).unwrap();
    state.data_len = MAX_MESSAGE_LEN - 64;
    state
}

#[test]
fn encryption_limit_errors_leave_state_and_output_untouched() {
    let mut enc = ChaCha20Poly1305Encryptor(near_limit());
    let mut out = [0xa5; 65];
    assert!(matches!(
        enc.do_encrypt_out(&[0; 65], &mut out),
        Err(SymmetricCipherError::StateError(_))
    ));
    assert_eq!(out, [0xa5; 65]);
    assert!(!enc.0.data_started);
    enc.do_update_aad(b"aad").unwrap();
    enc.do_encrypt_out(&[0; 63], &mut out[..63]).unwrap();
    assert_eq!(enc.0.cipher.remaining_bytes(), 1);
    let mut short = [0xa5; 2];
    assert!(matches!(
        enc.do_encrypt_out(&[0; 2], &mut short),
        Err(SymmetricCipherError::StateError(_))
    ));
    assert_eq!(short, [0xa5; 2]);
    enc.do_encrypt_out(&[0], &mut out[63..64]).unwrap();
    assert_eq!(enc.0.data_len, MAX_MESSAGE_LEN);
    enc.do_encrypt_out(&[], &mut []).unwrap();
    let mut reference = ChaCha20Poly1305Encryptor(near_limit());
    reference.do_update_aad(b"aad").unwrap();
    let mut expected = [0; 64];
    reference.do_encrypt_out(&[0; 64], &mut expected).unwrap();
    assert_eq!(out[..64], expected);
    assert_eq!(enc.do_final().unwrap(), reference.do_final().unwrap());
}

#[test]
fn inline_decryption_allows_the_last_ciphertext_block_plus_tag() {
    let mut enc = ChaCha20Poly1305Encryptor(near_limit());
    let mut inline = [0; 80];
    enc.do_encrypt_out(&[0x42; 64], &mut inline[..64]).unwrap();
    inline[64..].copy_from_slice(&enc.do_final().unwrap().0);
    let mut dec = ChaCha20Poly1305Decryptor { state: near_limit(), held: [0; 16], held_len: 0 };
    let mut out = [0xa5; 65];
    assert!(matches!(
        dec.do_decrypt_out(&[0; 81], &mut out),
        Err(SymmetricCipherError::StateError(_))
    ));
    assert_eq!(out, [0xa5; 65]);
    assert_eq!(dec.held_len, 0);
    assert!(!dec.state.data_started);
    assert_eq!(dec.do_decrypt_out(&inline, &mut out).unwrap(), 64);
    assert_eq!(dec.state.data_len, MAX_MESSAGE_LEN);
    assert_eq!(dec.do_final().unwrap().1, 0);
    assert_eq!(&out[..64], &[0x42; 64]);
    assert_eq!(out[64], 0xa5);
}

#[test]
fn detached_final_checks_the_limit_and_clears_its_buffer() {
    let mut dec = ChaCha20Poly1305Decryptor { state: near_limit(), held: [0; 16], held_len: 0 };
    // The update must reserve a possible inline tag. Only detached finalization can know
    // that these extra 16 bytes are actually ciphertext exceeding the counter limit.
    dec.do_decrypt_out(&[0; 80], &mut [0; 64]).unwrap();
    let mut out = [0xa5; 16];
    assert!(matches!(
        dec.do_final_out_detached(&[0; 16], &mut out),
        Err(SymmetricCipherError::StateError(_))
    ));
    assert_eq!(out, [0; 16]);
}

#[test]
fn aad_length_overflow_is_rejected_before_absorption() {
    let mut state = state();
    let mut reference = super::limits::state();
    state.aad_len = u64::MAX - 1;
    reference.aad_len = u64::MAX - 1;
    assert!(matches!(state.update_aad(&[1, 2]), Err(SymmetricCipherError::StateError(_))));
    assert_eq!(state.aad_len, u64::MAX - 1);
    state.update_aad(&[1]).unwrap();
    reference.update_aad(&[1]).unwrap();
    state.update_aad(&[]).unwrap();
    assert_eq!(state.aad_len, u64::MAX);
    assert_eq!(state.tag(), reference.tag());
}
