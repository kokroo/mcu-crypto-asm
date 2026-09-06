use mcu_crypto_asm::keccak::{sha3_256, sha3_512, shake128, shake256};

#[test]
fn test_sha3_256_empty() {
    let hash = sha3_256(b"");
    let expected = hex::decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a").unwrap();
    assert_eq!(&hash[..], &expected[..]);
}

#[test]
fn test_sha3_256_quick_brown_fox() {
    let hash = sha3_256(b"The quick brown fox jumps over the lazy dog");
    let expected = hex::decode("69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04").unwrap();
    assert_eq!(&hash[..], &expected[..]);
}

#[test]
fn test_sha3_512_empty() {
    let hash = sha3_512(b"");
    let expected = hex::decode("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26").unwrap();
    assert_eq!(&hash[..], &expected[..]);
}

#[test]
fn test_sha3_512_quick_brown_fox() {
    let hash = sha3_512(b"The quick brown fox jumps over the lazy dog");
    let expected = hex::decode("01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450").unwrap();
    assert_eq!(&hash[..], &expected[..]);
}

#[test]
fn test_shake128_quick_brown_fox() {
    let mut out = [0u8; 32];
    shake128(b"The quick brown fox jumps over the lazy dog", &mut out);
    let expected = hex::decode("f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e").unwrap();
    assert_eq!(&out[..], &expected[..]);
}

#[test]
fn test_shake256_quick_brown_fox() {
    let mut out = [0u8; 32];
    shake256(b"The quick brown fox jumps over the lazy dog", &mut out);
    let expected = hex::decode("2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca").unwrap();
    assert_eq!(&out[..], &expected[..]);
}
