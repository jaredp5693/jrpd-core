pub const JRPD_MAGIC_BYTES: u32 = 0x4A52_5044;
pub const JRPD_PROTOCOL_VERSION: u8 = 0x01;
pub const JRPD_HEADER_AAD_LEN: usize = 17;
pub const JRPD_GCM_NONCE_LEN: usize = 12;
pub const JRPD_GCM_TAG_LEN: usize = 16;
pub const JRPD_MIN_FRAME_LEN: usize =
    JRPD_HEADER_AAD_LEN + JRPD_GCM_NONCE_LEN + 4 + JRPD_GCM_TAG_LEN;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JrpdOpcode {
    NopPing = 0x0000_0001,
    SessionInit = 0x0000_0002,
    SessionRotateKey = 0x0000_0003,
    AckReceipt = 0x0000_0004,
    NackReject = 0x0000_0005,
    GetBalance = 0x0001_0001,
    MakeInvoice = 0x0001_0002,
    PayInvoice = 0x0001_0003,
    SettlementFinal = 0x0001_0004,
    QuorumAttestation = 0x0001_0005,
    TelemetrySync = 0x0002_0001,
    Ieee754BatchCast = 0x0002_0002,
    VmBytecodeExec = 0x0002_0003,
    RehashAuditProof = 0x0002_0004,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallRejectReason {
    FrameTruncated,
    InvalidMagic,
    UnsupportedVersion(u8),
    UnknownOperatorTag(u32),
}

impl JrpdOpcode {
    #[inline]
    pub const fn try_from_u32(raw: u32) -> Result<Self, FirewallRejectReason> {
        match raw {
            0x0000_0001 => Ok(Self::NopPing),
            0x0000_0002 => Ok(Self::SessionInit),
            0x0000_0003 => Ok(Self::SessionRotateKey),
            0x0000_0004 => Ok(Self::AckReceipt),
            0x0000_0005 => Ok(Self::NackReject),
            0x0001_0001 => Ok(Self::GetBalance),
            0x0001_0002 => Ok(Self::MakeInvoice),
            0x0001_0003 => Ok(Self::PayInvoice),
            0x0001_0004 => Ok(Self::SettlementFinal),
            0x0001_0005 => Ok(Self::QuorumAttestation),
            0x0002_0001 => Ok(Self::TelemetrySync),
            0x0002_0002 => Ok(Self::Ieee754BatchCast),
            0x0002_0003 => Ok(Self::VmBytecodeExec),
            0x0002_0004 => Ok(Self::RehashAuditProof),
            unknown => Err(FirewallRejectReason::UnknownOperatorTag(unknown)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JrpdHeader {
    pub version: u8,
    pub opcode: JrpdOpcode,
    pub seq_id: u64,
}

#[inline]
pub fn parse_and_filter_header(frame: &[u8]) -> Result<JrpdHeader, FirewallRejectReason> {
    if frame.len() < JRPD_MIN_FRAME_LEN {
        return Err(FirewallRejectReason::FrameTruncated);
    }
    let magic = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    if magic != JRPD_MAGIC_BYTES {
        return Err(FirewallRejectReason::InvalidMagic);
    }
    let version = frame[4];
    if version != JRPD_PROTOCOL_VERSION {
        return Err(FirewallRejectReason::UnsupportedVersion(version));
    }
    let raw_op = u32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]);
    let opcode = JrpdOpcode::try_from_u32(raw_op)?;
    let seq_id = u64::from_be_bytes([
        frame[9], frame[10], frame[11], frame[12],
        frame[13], frame[14], frame[15], frame[16],
    ]);
    Ok(JrpdHeader { version, opcode, seq_id })
}
