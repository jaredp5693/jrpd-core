#ifndef JRPD_VM_ISA_H
#define JRPD_VM_ISA_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <math.h>

#ifdef __cplusplus
extern "C" {
#endif

#define JRPD_VM_MAX_STACK_DEPTH     64U
#define JRPD_VM_MAX_LOCALS          16U
#define JRPD_VM_MAX_BYTECODE_LEN    2048U
#define JRPD_VM_DEFAULT_GAS_BUDGET  1024U
#define JRPD_VM_EPSILON_F64         1e-15

typedef enum {
    VM_OP_HALT          = 0x00,
    VM_OP_NOP           = 0x01,
    VM_OP_JMP           = 0x02,
    VM_OP_JMP_IF_FALSE  = 0x03,
    VM_OP_JMP_IF_TRUE   = 0x04,
    VM_OP_PUSH_U64      = 0x10,
    VM_OP_PUSH_F64      = 0x11,
    VM_OP_POP           = 0x12,
    VM_OP_DUP           = 0x13,
    VM_OP_SWAP          = 0x14,
    VM_OP_LOAD_LOCAL    = 0x15,
    VM_OP_STORE_LOCAL   = 0x16,
    VM_OP_ADD_F64       = 0x20,
    VM_OP_SUB_F64       = 0x21,
    VM_OP_MUL_F64       = 0x22,
    VM_OP_DIV_SAFE      = 0x23
} jrpd_vm_opcode_t;

typedef enum {
    VM_OK                   = 0x00,
    ERR_VM_INVALID_OPCODE   = 0x01,
    ERR_VM_STACK_OVERFLOW   = 0x02,
    ERR_VM_STACK_UNDERFLOW  = 0x03,
    ERR_VM_DIV_ZERO         = 0x04,
    ERR_VM_OUT_OF_GAS       = 0x05,
    ERR_VM_PC_OUT_OF_BOUNDS = 0x06,
    ERR_VM_NON_FINITE_FLOAT = 0x07,
    ERR_VM_INVALID_LOCAL    = 0x09,
    ERR_VM_EMPTY_RETURN     = 0x0A
} jrpd_vm_trap_t;

typedef struct {
    uint64_t       result_bits;
    uint32_t       gas_used;
    uint16_t       fault_pc;
    jrpd_vm_trap_t status;
} jrpd_vm_exec_result_t;

static inline double jrpd_bits_to_f64(uint64_t bits) {
    double val;
    memcpy(&val, &bits, sizeof(double));
    return val;
}

static inline uint64_t jrpd_f64_to_bits(double val) {
    uint64_t bits;
    memcpy(&bits, &val, sizeof(uint64_t));
    return bits;
}

static inline jrpd_vm_exec_result_t jrpd_vm_execute(
    const uint8_t *code,
    size_t code_len,
    uint32_t gas_limit
) {
    jrpd_vm_exec_result_t res = {0ULL, 0U, 0U, VM_OK};
    uint64_t stack[JRPD_VM_MAX_STACK_DEPTH];
    size_t sp = 0U, pc = 0U;

    if (code == NULL || code_len == 0U || code_len > JRPD_VM_MAX_BYTECODE_LEN) {
        res.status = ERR_VM_PC_OUT_OF_BOUNDS;
        return res;
    }
    if (gas_limit == 0U || gas_limit > JRPD_VM_DEFAULT_GAS_BUDGET) {
        gas_limit = JRPD_VM_DEFAULT_GAS_BUDGET;
    }

    while (pc < code_len) {
        res.fault_pc = (uint16_t)pc;
        uint8_t op = code[pc++];
        uint16_t cost = (op == VM_OP_HALT || op == VM_OP_NOP) ? 1U :
                        (op == VM_OP_PUSH_F64 || op == VM_OP_PUSH_U64) ? 2U :
                        (op == VM_OP_ADD_F64 || op == VM_OP_SUB_F64) ? 4U :
                        (op == VM_OP_MUL_F64) ? 6U :
                        (op == VM_OP_DIV_SAFE) ? 10U : 0U;
        if (cost == 0U) { res.status = ERR_VM_INVALID_OPCODE; return res; }
        if (res.gas_used + cost > gas_limit) { res.status = ERR_VM_OUT_OF_GAS; return res; }
        res.gas_used += cost;

        if (op == VM_OP_HALT) {
            if (sp == 0U) { res.status = ERR_VM_EMPTY_RETURN; return res; }
            res.result_bits = stack[sp - 1U];
            return res;
        } else if (op == VM_OP_PUSH_F64 || op == VM_OP_PUSH_U64) {
            if (pc + 8U > code_len) { res.status = ERR_VM_PC_OUT_OF_BOUNDS; return res; }
            if (sp >= JRPD_VM_MAX_STACK_DEPTH) { res.status = ERR_VM_STACK_OVERFLOW; return res; }
            uint64_t imm = 0ULL;
            for (size_t i = 0; i < 8U; ++i) imm = (imm << 8) | (uint64_t)code[pc + i];
            pc += 8U;
            if (op == VM_OP_PUSH_F64 && !isfinite(jrpd_bits_to_f64(imm))) {
                res.status = ERR_VM_NON_FINITE_FLOAT; return res;
            }
            stack[sp++] = imm;
        } else if (op == VM_OP_ADD_F64 || op == VM_OP_SUB_F64 || op == VM_OP_MUL_F64) {
            if (sp < 2U) { res.status = ERR_VM_STACK_UNDERFLOW; return res; }
            double b = jrpd_bits_to_f64(stack[--sp]);
            double a = jrpd_bits_to_f64(stack[--sp]);
            if (!isfinite(a) || !isfinite(b)) { res.status = ERR_VM_NON_FINITE_FLOAT; return res; }
            double out = (op == VM_OP_ADD_F64) ? (a + b) : (op == VM_OP_SUB_F64) ? (a - b) : (a * b);
            if (!isfinite(out)) { res.status = ERR_VM_NON_FINITE_FLOAT; return res; }
            stack[sp++] = jrpd_f64_to_bits(out);
        } else if (op == VM_OP_DIV_SAFE) {
            if (sp < 2U) { res.status = ERR_VM_STACK_UNDERFLOW; return res; }
            double b = jrpd_bits_to_f64(stack[--sp]);
            double a = jrpd_bits_to_f64(stack[--sp]);
            if (!isfinite(a) || !isfinite(b)) { res.status = ERR_VM_NON_FINITE_FLOAT; return res; }
            if (fabs(b) < JRPD_VM_EPSILON_F64) { res.status = ERR_VM_DIV_ZERO; return res; }
            double out = a / b;
            if (!isfinite(out)) { res.status = ERR_VM_NON_FINITE_FLOAT; return res; }
            stack[sp++] = jrpd_f64_to_bits(out);
        }
    }
    res.status = ERR_VM_PC_OUT_OF_BOUNDS;
    return res;
}

#ifdef __cplusplus
}
#endif
#endif
