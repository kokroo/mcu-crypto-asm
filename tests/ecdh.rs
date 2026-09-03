//! ECDH: agreement, SEC1 encoding, and rejection of hostile inputs.

use nistp_mcu::{ecdh, p256, p384, CurveParams};

fn roundtrip<const N: usize>(
    c: &CurveParams,
    name: &str,
    comb: &[([u32; N], [u32; N])],
    comb_d: usize,
    comb_t: usize,
) {
    let sk_a = {
        let mut b = vec![0u8; 4 * N];
        b[4 * N - 1] = 0x07;
        b[0] = 0x11;
        b
    };
    let sk_b = {
        let mut b = vec![0u8; 4 * N];
        b[4 * N - 1] = 0x2b;
        b[1] = 0x39;
        b
    };

    let mut pk_a = vec![0u8; 1 + 8 * N];
    let mut pk_b = vec![0u8; 1 + 8 * N];
    ecdh::derive_public_key::<N>(c, &sk_a, &mut pk_a, comb, comb_d, comb_t).unwrap();
    ecdh::derive_public_key::<N>(c, &sk_b, &mut pk_b, comb, comb_d, comb_t).unwrap();
    assert_eq!(pk_a[0], 0x04, "{name}: SEC1 uncompressed tag");

    let mut ss_a = vec![0u8; 4 * N];
    let mut ss_b = vec![0u8; 4 * N];
    ecdh::shared_secret::<N>(c, &sk_a, &pk_b, &mut ss_a).unwrap();
    ecdh::shared_secret::<N>(c, &sk_b, &pk_a, &mut ss_b).unwrap();
    assert_eq!(ss_a, ss_b, "{name}: both sides must agree");
    assert!(ss_a.iter().any(|b| *b != 0), "{name}: secret is all zeros");
}

#[test]
fn p256_ecdh_agrees() {
    roundtrip::<{ p256::N }>(
        &p256::CURVE,
        "p256",
        &nistp_mcu::comb_tables::P256_COMB,
        p256::COMB_D,
        p256::COMB_T,
    );
}

#[test]
fn p384_ecdh_agrees() {
    roundtrip::<{ p384::N }>(
        &p384::CURVE,
        "p384",
        &nistp_mcu::comb_tables::P384_COMB,
        p384::COMB_D,
        p384::COMB_T,
    );
}

/// The invalid-curve attack: a point that is not on the curve must be refused,
/// never silently multiplied.
#[test]
fn rejects_point_not_on_curve() {
    const N: usize = p256::N;
    let c = &p256::CURVE;
    let mut sk = vec![0u8; 4 * N];
    sk[4 * N - 1] = 0x09;

    let mut pk = vec![0u8; 1 + 8 * N];
    p256::derive_public_key(&sk, &mut pk).unwrap();
    // A valid key must be accepted...
    let mut out = vec![0u8; 4 * N];
    assert!(ecdh::shared_secret::<N>(c, &sk, &pk, &mut out).is_ok());

    // ...and the same key with one bit of y flipped must not be.
    let mut bad = pk.clone();
    bad[1 + 8 * N - 1] ^= 1;
    assert_eq!(
        ecdh::shared_secret::<N>(c, &sk, &bad, &mut out),
        Err(ecdh::Error::BadPoint),
        "a point off the curve must be rejected"
    );

    // A non-uncompressed tag is refused too.
    let mut bad_tag = pk.clone();
    bad_tag[0] = 0x02;
    assert_eq!(
        ecdh::shared_secret::<N>(c, &sk, &bad_tag, &mut out),
        Err(ecdh::Error::BadPoint)
    );
}

#[test]
fn rejects_out_of_range_scalars() {
    const N: usize = p256::N;
    let c = &p256::CURVE;
    let mut out = vec![0u8; 1 + 8 * N];

    let zero = vec![0u8; 4 * N];
    assert_eq!(
        p256::derive_public_key(&zero, &mut out),
        Err(ecdh::Error::BadScalar),
        "zero scalar"
    );

    // n itself is out of range (valid scalars are 1..n-1).
    let mut order_be = vec![0u8; 4 * N];
    for i in 0..N {
        let off = (N - 1 - i) * 4;
        order_be[off..off + 4].copy_from_slice(&c.order[i].to_be_bytes());
    }
    assert_eq!(
        p256::derive_public_key(&order_be, &mut out),
        Err(ecdh::Error::BadScalar),
        "scalar == n"
    );
}

/// Pin the SEC1 byte encoding against an independent computation. Two sides
/// agreeing proves consistency, not correctness -- a systematically wrong
/// endianness would agree with itself perfectly.
#[test]
fn p256_public_key_encoding_matches_oracle() {
    const N: usize = p256::N;
    let c = &p256::CURVE;
    let mut sk = vec![0u8; 4 * N];
    sk[0] = 0x11;
    sk[4 * N - 1] = 0x07;

    let mut pk = vec![0u8; 1 + 8 * N];
    p256::derive_public_key(&sk, &mut pk).unwrap();

    let want: [u8; 65] = [
        0x04, 0x42, 0x97, 0x19, 0x03, 0x75, 0x09, 0x96, 0x49, 0xfb, 0x9d, 0x03, 0x3d, 0x7d, 0xa4,
        0x0a, 0x89, 0x3b, 0x69, 0x16, 0x8b, 0xae, 0xb3, 0x0b, 0xc2, 0xde, 0xb8, 0xfd, 0xcf, 0x51,
        0x24, 0x66, 0xbe, 0xaf, 0xfd, 0x86, 0xc8, 0x63, 0xba, 0xa7, 0x44, 0xd9, 0x07, 0x61, 0x9e,
        0xea, 0xcc, 0x34, 0x98, 0x73, 0xbd, 0xe5, 0xd5, 0x41, 0x00, 0x96, 0x91, 0x01, 0x34, 0x2b,
        0xd2, 0x53, 0x16, 0xd2, 0x0e,
    ];
    assert_eq!(pk.as_slice(), &want[..], "SEC1 encoding of k*G");
}
