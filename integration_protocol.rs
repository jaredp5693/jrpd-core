use jrpd_core::{
    decode_and_verify_attestation, downcast_f128_to_f64_jrpd, encode_signed_attestation,
    execute_sandboxed_vm, open_and_rehash_frame, parse_and_filter_header, seal_frame,
    verify_bytecode_strict_alignment, CanonicalStateTuple, JrpdOpcode,
    PartitionedNonceGen, QuorumOutcome, RelayIdentity, RelayQuorumEngine, VmOpcode, VmTrap,
};
use k256::schnorr::SigningKey;
use sha2::{Digest, Sha256};

extern "C" {
    fn c_ffi_validate_header(buf: *const u8, len: usize, out_opcode: *mut u32) -> bool;
    fn c_ffi_vm_exec(code: *const u8, code_len: usize, gas_limit: u32, out_bits: *mut u64) -> u32;
}

fn sha256_arr(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[test]
fn test_full_jrpd_and_c_ffi_parity() {
    let key = [0x42u8; 32];
    let nonce_gen = PartitionedNonceGen::from_seed([0xAA, 0xBB, 0xCC, 0xDD]);
    let nonce = nonce_gen.next_nonce().unwrap();

    let mut code = Vec::new();
    code.push(VmOpcode::PushF64 as u8);
    code.extend_from_slice(&150_000.0f64.to_bits().to_be_bytes());
    code.push(VmOpcode::PushF64 as u8);
    code.extend_from_slice(&0.0025f64.to_bits().to_be_bytes());
    code.push(VmOpcode::MulF64 as u8);
    code.push(VmOpcode::PushF64 as u8);
    code.extend_from_slice(&10.0f64.to_bits().to_be_bytes());
    code.push(VmOpcode::AddF64 as u8);
    code.push(VmOpcode::Halt as u8);

    let frame = seal_frame(&key, &nonce, JrpdOpcode::VmBytecodeExec, 1, &code).unwrap();

    let mut c_op = 0u32;
    let c_valid = unsafe { c_ffi_validate_header(frame.as_ptr(), frame.len(), &mut c_op) };
    let r_hdr = parse_and_filter_header(&frame).unwrap();
    assert!(c_valid);
    assert_eq!(c_op, r_hdr.opcode as u32);

    let (_, _, verified_code, audit) = open_and_rehash_frame(&key, &frame).unwrap();
    assert!(audit.parity_verified);

    let r_out = execute_sandboxed_vm(&verified_code, &[], 1024).unwrap();
    let mut c_bits = 0u64;
    let c_status = unsafe { c_ffi_vm_exec(verified_code.as_ptr(), verified_code.len(), 1024, &mut c_bits) };
    assert_eq!(c_status, 0);
    assert_eq!(r_out.result_bits, c_bits);
    assert_eq!(f64::from_bits(r_out.result_bits), 385.0);

    let mut div_zero = Vec::new();
    div_zero.push(VmOpcode::PushF64 as u8);
    div_zero.extend_from_slice(&42.0f64.to_bits().to_be_bytes());
    div_zero.push(VmOpcode::PushF64 as u8);
    div_zero.extend_from_slice(&1e-18f64.to_bits().to_be_bytes());
    div_zero.push(VmOpcode::DivSafe as u8);
    div_zero.push(VmOpcode::Halt as u8);

    assert_eq!(execute_sandboxed_vm(&div_zero, &[], 1024).unwrap_err().trap, VmTrap::DivZero);
    let c_div_status = unsafe { c_ffi_vm_exec(div_zero.as_ptr(), div_zero.len(), 1024, std::ptr::null_mut()) };
    assert_eq!(c_div_status, 0x04);

    let mut bad_jmp = vec![VmOpcode::PushF64 as u8];
    bad_jmp.extend_from_slice(&1.0f64.to_bits().to_be_bytes());
    bad_jmp.push(VmOpcode::Jmp as u8);
    bad_jmp.extend_from_slice(&2u16.to_be_bytes());
    bad_jmp.push(VmOpcode::Halt as u8);
    assert!(verify_bytecode_strict_alignment(&bad_jmp).is_err());
    assert_eq!(downcast_f128_to_f64_jrpd(20000u128 << 112), 0x7FEF_FFFF_FFFF_FFFF);

    let sk = SigningKey::from_bytes(&[0x55u8; 32]).unwrap();
    let vk = *sk.verifying_key();
    let relay = RelayIdentity::new("wss://relay1.nexus.io", sha256_arr(b"SPKI_1")).unwrap();
    let preimage = sha256_arr(b"HTLC_SECRET");
    let tuple = CanonicalStateTuple { seq_id: 1, op_tag: 0x0001_0003, status_code: 200, result_digest: [7u8; 32] };
    let att = encode_signed_attestation(&sk, &tuple, [9u8; 32], Some(preimage));
    let (dec_t, dec_id, dec_pi) = decode_and_verify_attestation(&vk, &att).unwrap();
    let mut q = RelayQuorumEngine::new(5, Some(sha256_arr(&preimage)));
    assert_eq!(
        q.ingest_verified_response(&relay, dec_id, dec_t, dec_pi),
        QuorumOutcome::SettledByPreimage { preimage, winning_relay: relay }
    );
}
