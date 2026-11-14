#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod crypto;
pub mod ieee754;
pub mod opcodes;
pub mod quorum;
pub mod vm_isa;

pub use crypto::{
    open_and_rehash_frame, seal_frame, PartitionedNonceGen, RehashAuditDigest,
    JRPD_MAX_MTU_PAYLOAD,
};
pub use ieee754::{downcast_f128_to_f64_jrpd, F64_MAX_FINITE_BITS, F64_MIN_FINITE_BITS};
pub use opcodes::{
    parse_and_filter_header, FirewallRejectReason, JrpdHeader, JrpdOpcode, JRPD_GCM_NONCE_LEN,
    JRPD_GCM_TAG_LEN, JRPD_HEADER_AAD_LEN, JRPD_MAGIC_BYTES, JRPD_MIN_FRAME_LEN,
    JRPD_PROTOCOL_VERSION,
};
pub use quorum::{
    decode_and_verify_attestation, encode_signed_attestation, CanonicalStateTuple, QuorumOutcome,
    RelayIdentity, RelayQuorumEngine,
};
pub use vm_isa::{
    div_safe_f64, execute_sandboxed_vm, verify_bytecode_strict_alignment, VmExecOutcome, VmFault,
    VmOpcode, VmTrap, JRPD_VM_DEFAULT_GAS_BUDGET, JRPD_VM_EPSILON_F64, JRPD_VM_MAX_BYTECODE_LEN,
    JRPD_VM_MAX_LOCALS, JRPD_VM_MAX_STACK_DEPTH,
};
