//! The resumable / async scalar multiplication must be (a) identical to the
//! blocking one and (b) uniform in the scalar, so chunking cannot leak.

use mcu_crypto::{mul_scalar_yielding, p256, p384, CurveParams, Point, ScalarMul};
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// Drive a future to completion, counting how many times it yielded.
fn block_on<F: Future>(f: F) -> (F::Output, usize) {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    let mut yields = 0;
    loop {
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return (v, yields),
            Poll::Pending => yields += 1,
        }
    }
}

fn same_result<const N: usize>(c: &CurveParams, name: &str) {
    let g = Point::<N>::generator(c);
    let mut k = [0u32; N];
    for (i, limb) in k.iter_mut().enumerate() {
        *limb = 0x9E37_79B9u32.wrapping_mul(i as u32 + 1) ^ 0x1234_5678;
    }
    let want = g.mul_scalar(c, &k);

    // Every budget must produce the same point, including a zero budget
    // (clamped to 1) and a budget larger than the whole computation.
    for budget in [0u32, 1, 3, 17, 64, u32::MAX] {
        let mut st = ScalarMul::<N>::new(c, &g, &k);
        let got = loop {
            if let Some(p) = st.step(c, budget) {
                break p;
            }
        };
        assert_eq!(
            got.to_affine(&c.field),
            want.to_affine(&c.field),
            "{name}: budget {budget} disagreed with the blocking version"
        );
    }

    // The async wrapper must agree too.
    let (got, yields) = block_on(mul_scalar_yielding(c, &g, &k, 8));
    assert_eq!(
        got.to_affine(&c.field),
        want.to_affine(&c.field),
        "{name}: async wrapper disagreed"
    );
    assert!(yields > 8, "{name}: expected many yields, saw {yields}");
}

#[test]
fn p256_resumable_matches_blocking() {
    same_result::<{ p256::N }>(&p256::CURVE, "p256");
}

#[test]
fn p384_resumable_matches_blocking() {
    same_result::<{ p384::N }>(&p384::CURVE, "p384");
}

/// Chunking must not turn the scalar into a timing signal: every scalar has to
/// take the SAME number of point operations, and therefore the same number of
/// yields at a given budget.
#[test]
fn step_count_is_independent_of_the_scalar() {
    const N: usize = p256::N;
    let c = &p256::CURVE;
    let g = Point::<N>::generator(c);

    let scalars: [[u32; N]; 5] = [
        [1, 0, 0, 0, 0, 0, 0, 0],
        [0xFFFF_FFFF; N],
        [0, 0, 0, 0, 0, 0, 0, 0x8000_0000],
        [0x5555_5555; N],
        [0xDEAD_BEEF, 0, 0xFFFF_FFFF, 7, 0, 0x1234, 0, 0x9ABC],
    ];

    let mut counts = Vec::new();
    for k in &scalars {
        let mut st = ScalarMul::<N>::new(c, &g, k);
        let mut ops = 0u32;
        while st.step(c, 1).is_none() {
            ops += 1;
        }
        counts.push(ops);
    }
    assert!(
        counts.windows(2).all(|w| w[0] == w[1]),
        "step counts vary with the scalar - chunking would leak: {counts:?}"
    );

    // And it matches the advertised, scalar-free constant.
    assert_eq!(
        counts[0] + 1,
        ScalarMul::<N>::total_ops(),
        "total_ops() disagrees with the real step count"
    );

    // Same for the yield count through the async path.
    let ys: Vec<usize> = scalars
        .iter()
        .map(|k| block_on(mul_scalar_yielding(c, &g, k, 4)).1)
        .collect();
    assert!(
        ys.windows(2).all(|w| w[0] == w[1]),
        "yield counts vary with the scalar: {ys:?}"
    );
}

/// The yielding ECDH must agree with the blocking one, and must still reject
/// hostile input before doing any work.
#[test]
fn async_ecdh_matches_blocking_and_still_validates() {
    use mcu_crypto::ecdh;
    const N: usize = p256::N;
    let c = &p256::CURVE;

    let mut sk = vec![0u8; 4 * N];
    sk[0] = 0x11;
    sk[4 * N - 1] = 0x07;

    let mut pk_sync = vec![0u8; 1 + 8 * N];
    p256::derive_public_key(&sk, &mut pk_sync).unwrap();

    let mut pk_async = vec![0u8; 1 + 8 * N];
    let (r, yields) = block_on(p256::derive_public_key_yielding(&sk, &mut pk_async, 1));
    r.unwrap();
    assert_eq!(pk_sync, pk_async, "async derive disagreed with blocking");
    // Budget 1 means one comb iteration per poll, so the yield count tracks
    // the iteration count. Assert against the curve's own constant rather
    // than a hardcoded number, which goes stale whenever the comb is retuned.
    assert_eq!(
        yields,
        p256::COMB_D - 1,
        "derive should yield once per comb iteration"
    );

    let mut ss_sync = vec![0u8; 4 * N];
    let mut ss_async = vec![0u8; 4 * N];
    ecdh::shared_secret::<N>(c, &sk, &pk_sync, &mut ss_sync).unwrap();
    block_on(ecdh::shared_secret_yielding::<N>(
        c,
        &sk,
        &pk_sync,
        &mut ss_async,
        8,
    ))
    .0
    .unwrap();
    assert_eq!(ss_sync, ss_async, "async shared secret disagreed");

    // A point off the curve must be refused by the async path too.
    let mut bad = pk_sync.clone();
    bad[1 + 8 * N - 1] ^= 1;
    let (r, y) = block_on(ecdh::shared_secret_yielding::<N>(
        c,
        &sk,
        &bad,
        &mut ss_async,
        8,
    ));
    assert_eq!(r, Err(ecdh::Error::BadPoint));
    assert_eq!(y, 0, "validation must reject before doing any work");
}
