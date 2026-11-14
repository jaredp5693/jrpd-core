#ifndef JRPD_OPCODES_H
#define JRPD_OPCODES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define JRPD_MAGIC_BYTES        0x4A525044U
#define JRPD_PROTOCOL_VERSION   0x01U
#define JRPD_HEADER_AAD_LEN     17U
#define JRPD_GCM_NONCE_LEN      12U
#define JRPD_GCM_TAG_LEN        16U
#define JRPD_MIN_FRAME_LEN      (JRPD_HEADER_AAD_LEN + JRPD_GCM_NONCE_LEN + 4U + JRPD_GCM_TAG_LEN)

typedef enum {
    JRPD_OP_NOP_PING            = 0x00000001U,
    JRPD_OP_SESSION_INIT        = 0x00000002U,
    JRPD_OP_SESSION_ROTATE_KEY  = 0x00000003U,
    JRPD_OP_ACK_RECEIPT         = 0x00000004U,
    JRPD_OP_NACK_REJECT         = 0x00000005U,
    JRPD_OP_GET_BALANCE         = 0x00010001U,
    JRPD_OP_MAKE_INVOICE        = 0x00010002U,
    JRPD_OP_PAY_INVOICE         = 0x00010003U,
    JRPD_OP_SETTLEMENT_FINAL    = 0x00010004U,
    JRPD_OP_QUORUM_ATTESTATION  = 0x00010005U,
    JRPD_OP_TELEMETRY_SYNC      = 0x00020001U,
    JRPD_OP_IEEE754_BATCH_CAST  = 0x00020002U,
    JRPD_OP_VM_BYTECODE_EXEC    = 0x00020003U,
    JRPD_OP_REHASH_AUDIT_PROOF  = 0x00020004U
} jrpd_opcode_t;

static inline bool jrpd_validate_ingress_header(const uint8_t *buf, size_t len, uint32_t *out_opcode) {
    if (buf == NULL || len < JRPD_MIN_FRAME_LEN) return false;
    uint32_t magic = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                     ((uint32_t)buf[2] << 8)  |  (uint32_t)buf[3];
    if (magic != JRPD_MAGIC_BYTES || buf[4] != JRPD_PROTOCOL_VERSION) return false;

    uint32_t op = ((uint32_t)buf[5] << 24) | ((uint32_t)buf[6] << 16) |
                  ((uint32_t)buf[7] << 8)  |  (uint32_t)buf[8];
    switch (op) {
        case JRPD_OP_NOP_PING: case JRPD_OP_SESSION_INIT: case JRPD_OP_SESSION_ROTATE_KEY:
        case JRPD_OP_ACK_RECEIPT: case JRPD_OP_NACK_REJECT: case JRPD_OP_GET_BALANCE:
        case JRPD_OP_MAKE_INVOICE: case JRPD_OP_PAY_INVOICE: case JRPD_OP_SETTLEMENT_FINAL:
        case JRPD_OP_QUORUM_ATTESTATION: case JRPD_OP_TELEMETRY_SYNC:
        case JRPD_OP_IEEE754_BATCH_CAST: case JRPD_OP_VM_BYTECODE_EXEC:
        case JRPD_OP_REHASH_AUDIT_PROOF:
            if (out_opcode != NULL) *out_opcode = op;
            return true;
        default:
            return false;
    }
}

#ifdef __cplusplus
}
#endif
#endif
