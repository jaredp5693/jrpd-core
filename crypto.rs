use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use crate::opcodes::{
    parse_and_filter_header, JrpdOpcode, JRPD_HEADER_AAD_LEN, JRPD_MAGIC_BYTES,
    JRPD_PROTOCOL_VERSION,
};

pub const JRPD_MAX_MTU_PAYLOAD: usize = 1200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RehashAuditDigest {
    pub h_rx: String,
    pub h_plaintext: String,
    pub h_verify: String,
    pub parity_verified: bool,
}

pub struct PartitionedNonceGen {
    boot_id: [u8; 4],
    counter: AtomicU64,
}

impl PartitionedNonceGen {
    #[cfg(feature = "os-hardening")]
    pub fn new_from_os_csprng() -> Result<Self, &'static str> {
        let mut boot_id = [0u8; 4];
        let ret = unsafe {
            libc::getrandom(boot_id.as_mut_ptr() as *mut libc::c_void, boot_id.len(), 0)
        };
        if ret != 4 {
            return Err("Kernel getrandom(2) failed");
        }
        Ok(Self { boot_id, counter: AtomicU64::new(1) })
    }

    pub const fn from_seed(boot_id: [u8; 4]) -> Self {
        Self { boot_id, counter: AtomicU64::new(1) }
    }

    pub fn next_nonce(&self) -> Result<[u8; 12], &'static str> {
        let seq = self.counter.fetch_add(1, Ordering::SeqCst);
        if seq == u64::MAX {
            return Err("64-bit nonce counter exhausted; rotate key");
        }
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.boot_id);
        nonce[4..12].copy_from_slice(&seq.to_be_bytes());
        Ok(nonce)
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn seal_frame(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    opcode: JrpdOpcode,
    seq_id: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if plaintext.len() > JRPD_MAX_MTU_PAYLOAD {
        return Err("Payload exceeds JRPD_MAX_MTU_PAYLOAD (1200 bytes)");
    }
    let mut aad = [0u8; JRPD_HEADER_AAD_LEN];
    aad[0..4].copy_from_slice(&JRPD_MAGIC_BYTES.to_be_bytes());
    aad[4] = JRPD_PROTOCOL_VERSION;
    aad[5..9].copy_from_slice(&(opcode as u32).to_be_bytes());
    aad[9..17].copy_from_slice(&seq_id.to_be_bytes());

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Invalid AES-256 key")?;
    let ct = cipher
        .encrypt(Nonce::from_slice(nonce_bytes), Payload { msg: plaintext, aad: &aad })
        .map_err(|_| "AES-256-GCM encryption failed")?;

    let mut frame = Vec::with_capacity(33 + ct.len());
    frame.extend_from_slice(&aad);
    frame.extend_from_slice(nonce_bytes);
    frame.extend_from_slice(&(ct.len() as u32).to_be_bytes());
    frame.extend_from_slice(&ct);
    Ok(frame)
}

pub fn open_and_rehash_frame(
    key: &[u8; 32],
    raw_frame: &[u8],
) -> Result<(JrpdOpcode, u64, Vec<u8>, RehashAuditDigest), &'static str> {
    let header = parse_and_filter_header(raw_frame).map_err(|_| "Header rejected at boundary")?;
    let h_rx = sha256_hex(raw_frame);

    let aad = &raw_frame[0..17];
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&raw_frame[17..29]);

    let ct_len = u32::from_be_bytes([raw_frame[29], raw_frame[30], raw_frame[31], raw_frame[32]]) as usize;
    if raw_frame.len() != 33 + ct_len {
        return Err("Ciphertext length mismatch");
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Invalid AES-256 key")?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_arr), Payload { msg: &raw_frame[33..], aad })
        .map_err(|_| "AES-256-GCM authentication failed")?;

    let h_plaintext = sha256_hex(&plaintext);
    let re_sealed = seal_frame(key, &nonce_arr, header.opcode, header.seq_id, &plaintext)?;
    let h_verify = sha256_hex(&re_sealed);
    let parity_verified = h_rx == h_verify;

    Ok((
        header.opcode,
        header.seq_id,
        plaintext,
        RehashAuditDigest { h_rx, h_plaintext, h_verify, parity_verified },
    ))
}
