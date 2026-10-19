// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// A dependency-free SHA-256 (night-improve-5, the build lane's
// std-only law): the registry-prebuilt lane verifies the staged
// object's bytes against the ebpf-prebuilt/manifest.toml object pin
// before embedding them, and the pin is a sha256 - so the build
// script needs a sha256. Adding a hashing crate as a
// build-dependency would break the manifest's own rule (build.rs
// stays std-only; the Cargo.toml comment block records it), so the
// algorithm lives here: FIPS 180-4, the round constants and the
// padding law verbatim, no unsafe, no allocation beyond the two
// fixed-size working buffers.
//
// The suite below is the only thing that executes these vectors -
// `cargo test` never runs build-script tests; the standing runner is:
//   rustc --edition 2021 --test build.rs -o /tmp/zejtron-build-test
//     && /tmp/zejtron-build-test
// The vectors are the NIST FIPS 180-4 examples plus two block
// boundary shapes (55 bytes: padding fits the first block; 64 bytes:
// exact block edge forces the one-extra-padding-block path), hashed
// with coreutils sha256sum as the ground truth.

/// One SHA-256 digest over `data`, as 32 raw bytes.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    // FIPS 180-4 section 4.2.2: the first sixty-four primes' cube-root
    // fractional parts, the standard round constants.
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    // FIPS 180-4 section 5.3.3: the initial hash values, the first
    // eight primes' square-root fractional parts.
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Message padding (FIPS 180-4 section 5.1.1): the one bit, zeros
    // to 56 mod 64, then the 64-bit big-endian bit length. The buffer
    // is built by iteration, not allocation: walk full blocks, then
    // pad the tail (one or two blocks, decided by the tail length).
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let (full_blocks, tail) = data.as_chunks::<64>();
    for block in full_blocks {
        compress(&mut h, block, &K);
    }
    let mut last = [0u8; 128];
    last[..tail.len()].copy_from_slice(tail);
    last[tail.len()] = 0x80;
    let last_len = if tail.len() + 9 <= 64 { 64 } else { 128 };
    last[last_len - 8..last_len].copy_from_slice(&bit_len.to_be_bytes());
    let (pad_blocks, _) = last[..last_len].as_chunks::<64>();
    for block in pad_blocks {
        compress(&mut h, block, &K);
    }

    let mut digest = [0u8; 32];
    let (words, _) = digest.as_chunks_mut::<4>();
    for (word, slot) in h.iter().zip(words.iter_mut()) {
        slot.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// The FIPS 180-4 compression function over one 64-byte block.
fn compress(h: &mut [u32; 8], block: &[u8; 64], k: &[u32; 64]) {
    let mut w = [0u32; 64];
    let (words, _) = block.as_chunks::<4>();
    for (word, chunk) in w.iter_mut().zip(words.iter()) {
        *word = u32::from_be_bytes(*chunk);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    let rounds = [a, b, c, d, e, f, g, hh];
    for (slot, round) in h.iter_mut().zip(rounds) {
        *slot = slot.wrapping_add(round);
    }
}

/// Lowercase hex rendering of one digest - the manifest pins are hex
/// strings, so the comparison renders both sides the same way.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in sha256(data) {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_hex(data: &[u8]) -> String {
        sha256_hex(data)
    }

    #[test]
    fn empty_input_matches_the_fips_vector() {
        assert_eq!(
            digest_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn short_input_matches_the_fips_vector() {
        assert_eq!(
            digest_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn fips_two_block_vector_matches() {
        // The standard 56-byte example: message padding overflows the
        // first block, exercising the length trailer's placement.
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            digest_hex(input),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn block_boundary_inputs_match_coreutils() {
        // 55 bytes: padding fits the first block (tail + 1 + 8 = 64).
        // 64 bytes: exact block edge, the one-extra-padding-block path.
        let a55 = [b'a'; 55];
        let a64 = [b'a'; 64];
        assert_eq!(
            digest_hex(&a55),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
        );
        assert_eq!(
            digest_hex(&a64),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );
    }

    #[test]
    fn multi_block_input_is_length_sensitive() {
        // A 129-byte input spans three blocks; flipping one bit in the
        // final byte must change the digest (the avalanche sanity
        // check for the tail-block walk).
        let mut input = vec![b'x'; 129];
        let baseline = digest_hex(&input);
        input[128] ^= 1;
        assert_ne!(digest_hex(&input), baseline);
    }
}
