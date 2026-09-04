use mcu_crypto_asm::{p256, p384};

#[test]
fn p256_ecdsa_known_answer() {
    let d =
        hex::decode("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
    let k =
        hex::decode("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90").unwrap();
    let e =
        hex::decode("deadbeefcafebabe0123456789abcdefdeadbeefcafebabe0123456789abcdef").unwrap();

    let mut pk = [0u8; 65];
    p256::derive_public_key(&d, &mut pk).unwrap();
    let mut pk_comp = [0u8; 33];
    p256::derive_public_key_compressed(&d, &mut pk_comp).unwrap();

    let expected_qx = "471c3e758c4904285bba7e53118ed0f524adeb0757d25bd2f8e7b0d76dfa714c";
    let expected_qy = "dd520f7aca8a8b917acc37f51de8f0c9bbe3ad858382e702dc25a12d09f7a858";
    assert_eq!(&pk[1..33], hex::decode(expected_qx).unwrap().as_slice());
    assert_eq!(&pk[33..], hex::decode(expected_qy).unwrap().as_slice());

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    p256::ecdsa::sign(&d, &e, &k, &mut r, &mut s).unwrap();

    let expected_r = "77186fee3e281f9d033a64994f823f7e384151e7383090c3c2954340f2951536";
    let expected_s = "ae4c3a2845bca18a53eba403b539e800cd7d253a17b2e9a27475633d8da8b130";
    assert_eq!(r.as_slice(), hex::decode(expected_r).unwrap().as_slice());
    assert_eq!(s.as_slice(), hex::decode(expected_s).unwrap().as_slice());

    // Verify uncompressed
    assert!(p256::ecdsa::verify(&pk, &e, &r, &s).is_ok());
    // Verify compressed
    assert!(p256::ecdsa::verify(&pk_comp, &e, &r, &s).is_ok());

    // Tampering test: 1 bit flip in message
    let mut bad_e = e.clone();
    bad_e[0] ^= 1;
    assert!(p256::ecdsa::verify(&pk, &bad_e, &r, &s).is_err());

    // Tampering test: 1 bit flip in r
    let mut bad_r = r;
    bad_r[0] ^= 1;
    assert!(p256::ecdsa::verify(&pk, &e, &bad_r, &s).is_err());

    // Tampering test: 1 bit flip in s
    let mut bad_s = s;
    bad_s[0] ^= 1;
    assert!(p256::ecdsa::verify(&pk, &e, &r, &bad_s).is_err());
}

#[test]
fn p384_ecdsa_known_answer() {
    let d = hex::decode("000000000000000000000000000000001234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
    let k = hex::decode("00000000000000000000000000000000a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90").unwrap();
    let e = hex::decode("00000000000000000000000000000000deadbeefcafebabe0123456789abcdefdeadbeefcafebabe0123456789abcdef").unwrap();

    let mut pk = [0u8; 97];
    p384::derive_public_key(&d, &mut pk).unwrap();
    let mut pk_comp = [0u8; 49];
    p384::derive_public_key_compressed(&d, &mut pk_comp).unwrap();

    let expected_qx = "c787d37c05c2c199a12c7e85baa2354aaad83260c08a156dce611b3cdfce17076f28fc663c8a5f74b82e910595e2d6b5";
    let expected_qy = "c8cc2cd81f71dc13134d55f1ae20a8d70ee52add3b9ab0387e96efb2ccfae6da6b81128990b1a142c2bfc26119801766";
    assert_eq!(&pk[1..49], hex::decode(expected_qx).unwrap().as_slice());
    assert_eq!(&pk[49..], hex::decode(expected_qy).unwrap().as_slice());

    let mut r = [0u8; 48];
    let mut s = [0u8; 48];
    p384::ecdsa::sign(&d, &e, &k, &mut r, &mut s).unwrap();

    let expected_r = "50f353d6cb502b3bc6146cb602519e72940ffc7fa7bb2356d82020c8c3fa6645528fc4cffb79fc2f476672ef908f9f1e";
    let expected_s = "67fabf5710c8e61e18ca6c0d94b4b809ebfd08a7d59743a54f641af50446ed5302e1c019478fc02f8999cc033fe440bc";
    assert_eq!(r.as_slice(), hex::decode(expected_r).unwrap().as_slice());
    assert_eq!(s.as_slice(), hex::decode(expected_s).unwrap().as_slice());

    // Verify uncompressed
    assert!(p384::ecdsa::verify(&pk, &e, &r, &s).is_ok());
    // Verify compressed
    assert!(p384::ecdsa::verify(&pk_comp, &e, &r, &s).is_ok());

    // Tampering test: 1 bit flip in message
    let mut bad_e = e.clone();
    bad_e[0] ^= 1;
    assert!(p384::ecdsa::verify(&pk, &bad_e, &r, &s).is_err());

    // Tampering test: 1 bit flip in r
    let mut bad_r = r;
    bad_r[0] ^= 1;
    assert!(p384::ecdsa::verify(&pk, &e, &bad_r, &s).is_err());

    // Tampering test: 1 bit flip in s
    let mut bad_s = s;
    bad_s[0] ^= 1;
    assert!(p384::ecdsa::verify(&pk, &e, &r, &bad_s).is_err());
}



#[test]
fn rejects_invalid_signatures() {
    let d = [1u8; 32];
    let mut pk = [0u8; 65];
    p256::derive_public_key(&d, &mut pk).unwrap();
    let e = [2u8; 32];

    // r = 0 or s = 0 must be rejected
    let zero = [0u8; 32];
    let one = [1u8; 32];
    assert_eq!(
        p256::ecdsa::verify(&pk, &e, &zero, &one),
        Err(mcu_crypto_asm::ecdsa::Error::BadSignature)
    );
    assert_eq!(
        p256::ecdsa::verify(&pk, &e, &one, &zero),
        Err(mcu_crypto_asm::ecdsa::Error::BadSignature)
    );

    // r >= n must be rejected
    let mut order_be = [0u8; 32];
    for (i, w) in p256::CURVE.order.iter().rev().enumerate() {
        order_be[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
    }
    assert_eq!(
        p256::ecdsa::verify(&pk, &e, &order_be, &one),
        Err(mcu_crypto_asm::ecdsa::Error::BadSignature)
    );
    assert_eq!(
        p256::ecdsa::verify(&pk, &e, &one, &order_be),
        Err(mcu_crypto_asm::ecdsa::Error::BadSignature)
    );
}
