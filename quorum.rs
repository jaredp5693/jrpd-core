use alloc::{collections::{BTreeMap, BTreeSet}, format, string::String, vec::Vec};
use k256::schnorr::{signature::{Signer, Verifier}, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayIdentity {
    pub canonical_uri: String,
    pub spki_sha256: [u8; 32],
}

impl RelayIdentity {
    pub fn new(raw_uri: &str, spki_sha256: [u8; 32]) -> Result<Self, &'static str> {
        let trimmed = raw_uri.trim().to_ascii_lowercase();
        let (scheme, rest) = trimmed.split_once("://").ok_or("Missing URI scheme")?;
        if scheme != "wss" && scheme != "ws" {
            return Err("Unsupported relay scheme");
        }
        let host_port = rest.split('/').next().unwrap_or("");
        if host_port.is_empty() {
            return Err("Empty relay host");
        }
        let host = if scheme == "wss" {
            host_port.strip_suffix(":443").unwrap_or(host_port)
        } else {
            host_port.strip_suffix(":80").unwrap_or(host_port)
        };
        Ok(Self { canonical_uri: format!("{scheme}://{host}"), spki_sha256 })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalStateTuple {
    pub seq_id: u64,
    pub op_tag: u32,
    pub status_code: u16,
    pub result_digest: [u8; 32],
}

impl CanonicalStateTuple {
    pub fn to_bytes(&self) -> [u8; 46] {
        let mut out = [0u8; 46];
        out[0..8].copy_from_slice(&self.seq_id.to_be_bytes());
        out[8..12].copy_from_slice(&self.op_tag.to_be_bytes());
        out[12..14].copy_from_slice(&self.status_code.to_be_bytes());
        out[14..46].copy_from_slice(&self.result_digest);
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 46 { return Err("Tuple too short"); }
        let mut result_digest = [0u8; 32];
        result_digest.copy_from_slice(&buf[14..46]);
        Ok(Self {
            seq_id: u64::from_be_bytes(buf[0..8].try_into().unwrap()),
            op_tag: u32::from_be_bytes(buf[8..12].try_into().unwrap()),
            status_code: u16::from_be_bytes(buf[12..14].try_into().unwrap()),
            result_digest,
        })
    }
}

pub fn encode_signed_attestation(
    sk: &SigningKey,
    tuple: &CanonicalStateTuple,
    event_id: [u8; 32],
    preimage: Option<[u8; 32]>,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(175);
    msg.extend_from_slice(&tuple.to_bytes());
    msg.extend_from_slice(&event_id);
    match preimage {
        Some(pi) => { msg.push(1); msg.extend_from_slice(&pi); }
        None => { msg.push(0); msg.extend_from_slice(&[0u8; 32]); }
    }
    let sig: Signature = sk.sign(&msg);
    msg.extend_from_slice(&sig.to_bytes());
    msg
}

pub fn decode_and_verify_attestation(
    vk: &VerifyingKey,
    buf: &[u8],
) -> Result<(CanonicalStateTuple, [u8; 32], Option<[u8; 32]>), &'static str> {
    if buf.len() != 175 { return Err("Invalid attestation length"); }
    let sig_bytes: [u8; 64] = buf[111..175].try_into().unwrap();
    let sig = Signature::try_from(&sig_bytes[..]).map_err(|_| "Malformed BIP-340 sig")?;
    vk.verify(&buf[0..111], &sig).map_err(|_| "BIP-340 verification failed")?;

    let tuple = CanonicalStateTuple::from_bytes(&buf[0..46])?;
    let mut event_id = [0u8; 32];
    event_id.copy_from_slice(&buf[46..78]);
    let preimage = if buf[78] == 1 {
        let mut pi = [0u8; 32];
        pi.copy_from_slice(&buf[79..111]);
        Some(pi)
    } else {
        None
    };
    Ok((tuple, event_id, preimage))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumOutcome {
    Pending { current_max_votes: usize, required: usize },
    SettledByPreimage { preimage: [u8; 32], winning_relay: RelayIdentity },
    CommittedByQuorum { state: CanonicalStateTuple, votes: usize },
}

pub struct RelayQuorumEngine {
    pub quorum_m: usize,
    pub expected_payment_hash: Option<[u8; 32]>,
    pub terminal_state: Option<QuorumOutcome>,
    votes_by_tuple: BTreeMap<CanonicalStateTuple, BTreeSet<[u8; 32]>>,
}

impl RelayQuorumEngine {
    pub fn new(total_relays_n: usize, expected_payment_hash: Option<[u8; 32]>) -> Self {
        let quorum_m = if total_relays_n >= 3 { (total_relays_n / 2) + 1 } else { total_relays_n.max(1) };
        Self { quorum_m, expected_payment_hash, terminal_state: None, votes_by_tuple: BTreeMap::new() }
    }

    pub fn ingest_verified_response(
        &mut self,
        relay: &RelayIdentity,
        _event_id: [u8; 32],
        tuple: CanonicalStateTuple,
        preimage: Option<[u8; 32]>,
    ) -> QuorumOutcome {
        if let Some(ref settled) = self.terminal_state {
            return settled.clone();
        }
        if let (Some(expected), Some(pi)) = (self.expected_payment_hash, preimage) {
            let mut h = Sha256::new();
            h.update(pi);
            let digest: [u8; 32] = h.finalize().into();
            if digest == expected {
                let out = QuorumOutcome::SettledByPreimage { preimage: pi, winning_relay: relay.clone() };
                self.terminal_state = Some(out.clone());
                return out;
            }
        }
        let voters = self.votes_by_tuple.entry(tuple.clone()).or_default();
        voters.insert(relay.spki_sha256);
        let count = voters.len();
        if count >= self.quorum_m {
            let out = QuorumOutcome::CommittedByQuorum { state: tuple, votes: count };
            self.terminal_state = Some(out.clone());
            return out;
        }
        QuorumOutcome::Pending { current_max_votes: count, required: self.quorum_m }
    }
}
