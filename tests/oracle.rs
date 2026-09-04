//! Correctness of the field arithmetic against `num-bigint`.
//!
//! The oracle is deliberately dumb and independent: plain bignum `a * b % p`.
//! If Montgomery form, CIOS, the conditional subtraction or the generated
//! constants are wrong anywhere, these fail.

use mcu_crypto_asm::{p256, p384, Fe, Params};
use num_bigint::BigUint;
use num_traits::{One, Zero};

fn to_big(limbs: &[u32]) -> BigUint {
    let mut bytes = Vec::with_capacity(limbs.len() * 4);
    for l in limbs {
        bytes.extend_from_slice(&l.to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}

fn from_big<const N: usize>(x: &BigUint) -> [u32; N] {
    let mut bytes = x.to_bytes_le();
    bytes.resize(N * 4, 0);
    let mut out = [0u32; N];
    for i in 0..N {
        out[i] = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
    }
    out
}

/// Deterministic xorshift — no rand dependency, and reproducible failures.
struct Rng(u64);
impl Rng {
    fn next_u32(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        (x >> 32) as u32
    }
    /// A uniform-ish value in `[0, p)`.
    fn field_elem<const N: usize>(&mut self, p: &BigUint) -> BigUint {
        let mut limbs = [0u32; N];
        for l in limbs.iter_mut() {
            *l = self.next_u32();
        }
        to_big(&limbs) % p
    }
}

fn check_curve<const N: usize>(f: &Params, name: &str) {
    let p = to_big(f.p);
    let mut rng = Rng(0x2545F4914F6CDD1D);

    // --- round trip ---
    for _ in 0..200 {
        let a = rng.field_elem::<N>(&p);
        let fe = Fe::<N>::from_int(f, &from_big::<N>(&a));
        assert_eq!(to_big(&fe.to_int(f)), a, "{name}: round trip");
    }

    // --- multiplication ---
    for _ in 0..500 {
        let a = rng.field_elem::<N>(&p);
        let b = rng.field_elem::<N>(&p);
        let fa = Fe::<N>::from_int(f, &from_big::<N>(&a));
        let fb = Fe::<N>::from_int(f, &from_big::<N>(&b));
        let got = to_big(&fa.mul(f, &fb).to_int(f));
        assert_eq!(got, (&a * &b) % &p, "{name}: {a} * {b}");
    }

    // --- squaring ---
    for _ in 0..300 {
        let a = rng.field_elem::<N>(&p);
        let fa = Fe::<N>::from_int(f, &from_big::<N>(&a));
        assert_eq!(
            to_big(&fa.sqr(f).to_int(f)),
            (&a * &a) % &p,
            "{name}: sqr {a}"
        );
    }

    // --- add / sub ---
    for _ in 0..500 {
        let a = rng.field_elem::<N>(&p);
        let b = rng.field_elem::<N>(&p);
        let fa = Fe::<N>::from_int(f, &from_big::<N>(&a));
        let fb = Fe::<N>::from_int(f, &from_big::<N>(&b));
        assert_eq!(
            to_big(&fa.add(f, &fb).to_int(f)),
            (&a + &b) % &p,
            "{name}: add"
        );
        assert_eq!(
            to_big(&fa.sub(f, &fb).to_int(f)),
            (&a + &p - &b) % &p,
            "{name}: sub"
        );
    }

    // --- div2 ---
    let inv2 = (&p + 1u32) / 2u32;
    for _ in 0..500 {
        let a = rng.field_elem::<N>(&p);
        let fa = Fe::<N>::from_int(f, &from_big::<N>(&a));
        assert_eq!(
            to_big(&fa.div2(f).to_int(f)),
            (&a * &inv2) % &p,
            "{name}: div2"
        );
    }

    // --- edge cases: these are where carry handling breaks ---
    let edges = vec![
        BigUint::zero(),
        BigUint::one(),
        &p - 1u32,
        &p - 2u32,
        (&p - 1u32) / 2u32,
        BigUint::one() << (32 * N - 1),
        (BigUint::one() << (32 * (N - 1))) - 1u32,
    ];
    for a in &edges {
        for b in &edges {
            let fa = Fe::<N>::from_int(f, &from_big::<N>(a));
            let fb = Fe::<N>::from_int(f, &from_big::<N>(b));
            assert_eq!(
                to_big(&fa.mul(f, &fb).to_int(f)),
                (a * b) % &p,
                "{name}: edge mul {a} * {b}"
            );
            assert_eq!(
                to_big(&fa.add(f, &fb).to_int(f)),
                (a + b) % &p,
                "{name}: edge add {a} + {b}"
            );
            assert_eq!(
                to_big(&fa.sub(f, &fb).to_int(f)),
                (a + &p - b) % &p,
                "{name}: edge sub {a} - {b}"
            );
        }
    }

    // --- identities ---
    let one = Fe::<N>::from_int(f, &from_big::<N>(&BigUint::one()));
    for _ in 0..100 {
        let a = rng.field_elem::<N>(&p);
        let fa = Fe::<N>::from_int(f, &from_big::<N>(&a));
        assert!(fa.mul(f, &one).ct_eq(&fa), "{name}: a*1 == a");
        assert!(fa.sub(f, &fa).is_zero(), "{name}: a-a == 0");
        // Montgomery form of 1 must equal R mod p from the generated params.
        assert_eq!(one.as_mont_limbs().as_slice(), f.one, "{name}: R constant");
    }

    // --- square root ---
    for _ in 0..100 {
        let a = rng.field_elem::<N>(&p);
        let fa = Fe::<N>::from_int(f, &from_big::<N>(&a));
        let sqr = fa.sqr(f);
        let root = sqr.sqrt(f).expect("quadratic residue must have sqrt");
        assert!(root.sqr(f).ct_eq(&sqr), "{name}: root^2 == sqr");
    }
    assert!(
        Fe::<N>::ZERO.sqrt(f).unwrap().is_zero(),
        "{name}: sqrt(0) == 0"
    );
}

#[test]
fn p256_field_matches_bigint() {
    check_curve::<{ p256::N }>(&p256::FIELD, "p256");
}

#[test]
fn p384_field_matches_bigint() {
    check_curve::<{ p384::N }>(&p384::FIELD, "p384");
}

/// The whole design assumes `n0' == 1`. Prove it from the modulus itself.
#[test]
fn n0inv_is_one_for_both_primes() {
    for (name, f) in [("p256", &p256::FIELD), ("p384", &p384::FIELD)] {
        assert_eq!(f.p[0], 0xFFFF_FFFF, "{name}: p is not -1 mod 2^32");
        assert_eq!(f.n0inv, 1, "{name}: n0inv must be 1");
        // -p^-1 mod 2^32 == 1  <=>  p * 1 == -1 mod 2^32
        assert_eq!(f.p[0].wrapping_mul(f.n0inv), 0xFFFF_FFFF, "{name}");
    }
}

fn check_scalar<const N: usize>(c: &mcu_crypto_asm::CurveParams, name: &str) {
    let order = to_big(c.order);
    let mut rng = Rng(0x1337_CAFE_DEAD_BEEF);

    // --- round trip ---
    for _ in 0..100 {
        let s = rng.field_elem::<N>(&order);
        let sc = mcu_crypto_asm::Scalar::<N>::from_int(c, &from_big::<N>(&s));
        assert_eq!(to_big(&sc.to_int(c)), s, "{name}: scalar round trip");
    }

    // --- add / sub / mul / sqr ---
    for _ in 0..200 {
        let a = rng.field_elem::<N>(&order);
        let b = rng.field_elem::<N>(&order);
        let sa = mcu_crypto_asm::Scalar::<N>::from_int(c, &from_big::<N>(&a));
        let sb = mcu_crypto_asm::Scalar::<N>::from_int(c, &from_big::<N>(&b));

        assert_eq!(
            to_big(&sa.add(c, &sb).to_int(c)),
            (&a + &b) % &order,
            "{name}: scalar add"
        );
        assert_eq!(
            to_big(&sa.sub(c, &sb).to_int(c)),
            (&a + &order - &b) % &order,
            "{name}: scalar sub"
        );
        assert_eq!(
            to_big(&sa.mul(c, &sb).to_int(c)),
            (&a * &b) % &order,
            "{name}: scalar mul"
        );
        assert_eq!(
            to_big(&sa.sqr(c).to_int(c)),
            (&a * &a) % &order,
            "{name}: scalar sqr"
        );
    }

    // --- inversion ---
    for _ in 0..50 {
        let a = rng.field_elem::<N>(&order);
        if a.is_zero() {
            continue;
        }
        let sa = mcu_crypto_asm::Scalar::<N>::from_int(c, &from_big::<N>(&a));
        let inv = sa.invert(c).expect("nonzero scalar has inverse");
        let one = sa.mul(c, &inv);
        assert_eq!(
            to_big(&one.to_int(c)),
            BigUint::one(),
            "{name}: a * a^-1 == 1 mod order"
        );
    }
}

#[test]
fn p256_scalar_matches_bigint() {
    check_scalar::<{ p256::N }>(&p256::CURVE, "p256 scalar");
}

#[test]
fn p384_scalar_matches_bigint() {
    check_scalar::<{ p384::N }>(&p384::CURVE, "p384 scalar");
}
