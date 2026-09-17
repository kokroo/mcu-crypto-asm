# Authors and Contributors

## Lead Author and Architect
- **Shiv Kokroo** ([@kokroo](https://github.com/kokroo))
  - Original Target 5 (Xtensa LX7: ESP32-S2 / ESP32-S3) unrolled Montgomery arithmetic engine (`asm/xtensa_lx7.S`, `asm/xtensa_lx7_call0.S`, `gen/gen_asm_xtensa.py`) utilizing branchless `SALTU` carry emulation for P-256 and P-384.
  - Original Target 1 (ARMv7E-M / ARMv8-M) 12-limb unrolled `UMAAL` Montgomery arithmetic engine for NIST P-384 (`asm/cortex_m4.S`, `gen/gen_asm_cortex_m4.py`) with VFP register allocation.
  - Fast Inversionless Projective ECDSA verification ($r \cdot Z^2 \equiv X \pmod p$) eliminating modular field inversion $\pmod p$.
  - Interleaved simultaneous double-scalar multiplication (`PointJacobian::lincomb` / Shamir's Trick) halving point doublings for P-256 and P-384.
  - Montgomery affine batch inversion and Comb fixed-base multiplication tables (`src/comb_tables.rs`).
  - Target 2 (ARMv6-M) secp256k1 Comba arithmetic engine (`src/secp256k1.rs`) and RSA CIOS Montgomery engine (`src/rsa.rs`).
  - Unified multi-target runtime dispatch architecture (`src/backend/`) and Embassy cryptographic framework drivers (`src/embassy.rs`).

## Upstream Authors & Prior Art
`mcu-crypto-asm` builds upon groundbreaking work by the cryptographic and embedded systems community:

- **Emil Lenngren** ([@Emill](https://github.com/Emill))
  - `P256-Cortex-M4`: Cortex-M4 P-256 UMAAL Montgomery field multiplication, squaring, modular add/sub, and Jacobian doubling.
  - `P256-cortex-ecdh`: Cortex-M0/M0+ Thumb-1 P-256 arithmetic.
  - `rsa-armv7`: Cortex-M bignum arithmetic engine (`bignum_asm.S`).
  - `X25519-Cortex-M4`: Cortex-M4 Curve25519/X25519 field arithmetic.
- **Dario Nieuwenhuis / Dirbaio & Embassy Project** ([@embassy-rs](https://github.com/embassy-rs))
  - `cortex25519`: Target 1 X25519 and Ed25519 point arithmetic assembly.
- **Thomas Pornin** ([@pornin](https://github.com/pornin) / BearSSL)
  - `x25519-cm0`: Constant-time pure 16-bit Thumb-1 X25519 assembly (`cortex_m0_curve25519.S`).
  - `BearSSL`: Constant-time bitsliced AES S-box (Boyar-Peralta logic minimization) and `ghash_ctmul32` Karatsuba multiplier.
- **Alexandre Adomnicăi** ([@Rvch7](https://github.com/Rvch7)) & **Thomas Peyrin**
  - `Fixslicing-AES`: Target 1 Fixsliced AES-128/256-CTR constant-time implementation.
  - ARMv7-M Keccak-P 32-bit interleaved bit-slice representation.
- **Andy Polyakov** & **The OpenSSL Project Authors**
  - `ghash-armv4.pl` / CRYPTOGAMS: Target 1 GHASH 4-bit polynomial multiplier.
  - `sha512-armv4.pl`: Target 1 SHA-512 & SHA-384 paired register assembly.
  - `chacha-armv4.pl`: ChaCha20 quarter-round unrolling inspiration.
- **Andrew Moon** ([@floodyberry](https://github.com/floodyberry))
  - `poly1305-opt` and `poly1305-donna`: Target 1 Poly1305 26-bit and 44-bit limb accumulation with `UMAAL`/`UMLAL`.
- **Junhao Huang** ([BNU-HKBU UIC](https://eprint.iacr.org/2022/956.pdf))
  - Plantard arithmetic and fast NTT/InvNTT assembly for Kyber / ML-KEM on Cortex-M4.
- **PQM4 Contributors** (Amin Abdulrahman, Vincent Hwang, Matthias J. Kannwischer, Nele Mentens, Joost Rijneveld, Peter Schwabe, Ko Stoffelen, Julian Wälde)
  - Hand-written DSP SIMD NTT/InvNTT/Basemul implementations for Post-Quantum Cryptography (ML-KEM and ML-DSA).
- **Mick de Pauw** ([@Mickdep](https://github.com/Mickdep))
  - ChaCha20 register-packed assembly optimization for Cortex-M4.
- **Kenneth MacKay** ([@kmackay](https://github.com/kmackay))
  - `micro-ecc`: secp256k1 compact arithmetic inspiration.
- **Ronny Van Keer & eXtended Keccak Code Package (XKCP)**
  - Keccak-P[1600] bit-slice implementation techniques.
- **Ana Helena Sánchez & Björn Haase**
  - Public domain µNaCl 256x256->512 multiplication/squaring for ARM Cortex-M0.
