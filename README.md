# `jrpd-core`

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust: 1.78+](https://img.shields.io/badge/Rust-1.78%2B-orange.svg)](#build--verification)
[![no_std Compatible](https://img.shields.io/badge/no__std-compatible-brightgreen.svg)](#architecture)

**Deterministic Cryptographic Wire Framing, Bit-Exact IEEE-754 Conditioning, Sandboxed Stack VM, and Sybil-Resistant `BIP-340` Quorum Finality for Autonomous Agents & Nostr/Lightning Settlement Rails.**

`jrpd-core` is the open-source reference implementation of **JRPD** (*Jared's Reliable Protocol Definition*), engineered to decouple stateless cloud/agent execution from sovereign cryptographic custody while eliminating relay packet reordering, floating-point rounding drift, and hot-wallet key exposure.

## Core Architectural Pillars

1. **Kernel-Hardened Wire Framing (`17-Byte AAD` + `AES-256-GCM`):**
   - Canonical binary header (`Magic: 0x4A525044` | `Version: 0x01` | `32-bit Op-Tag` | `64-bit Monotonic Seq-ID`) authenticated directly as GCM Additional Authenticated Data (`AAD`).
   - Strict `1200-byte` MTU payload ceiling (`JRPD_MAX_MTU_PAYLOAD`) prevents IPv4/IPv6 fragmentation and enables single-instruction `nftables` / `eBPF` kernel ingress filtering.
   - Collision-free 96-bit nonces concatenate a 32-bit OS CSPRNG `boot_id` (`getrandom(2)`) with a monotonic `AtomicU64` counter.
2. **Bit-Exact IEEE-754 `binary128` -> `binary64` GRS Conditioning:**
   - Pure-integer bitwise Guard, Round, and Sticky (`GRS`) truncation with Round-to-Nearest, Ties-to-Even parity and finite saturation clamping (`±DBL_MAX` / `0x7FEFFFFFFFFFFFFF`).
3. **Zero-Heap Sandboxed Stack VM (`ISA v1`):**
   - 38-opcode deterministic bytecode interpreter (`no_std` compatible) with static gas metering, a 256-byte instruction-boundary jump-alignment bitmask (`valid_op_starts`), and `DIV_SAFE` epsilon traps (`|B| < 1e-15`).
4. **Sybil-Resistant `M-of-N` & `1-of-N` `BIP-340` Quorum Engine:**
   - **Tier 1 (`1-of-N` Preimage Finality):** The first valid `BIP-340` Schnorr-signed receipt carrying a preimage matching `SHA256(preimage) == payment_hash` settles immediately.
   - **Tier 2 (`M-of-N` Quorum):** Non-preimage state transitions commit at strict majority (`M = floor(N/2) + 1`), deduplicated by normalized RFC 3986 URI + SHA-256 TLS `SPKI` pin.

## Build & Verification

```bash
cargo test --all-features -- --nocapture
cargo test --release --test fuzz_ieee754_100k -- --nocapture
cargo check --no-default-features
```

## License

Dual-licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
