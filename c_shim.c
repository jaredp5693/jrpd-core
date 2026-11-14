#include "jrpd_opcodes.h"
#include "jrpd_vm_isa.h"

bool c_ffi_validate_header(const uint8_t *buf, size_t len, uint32_t *out_opcode) {
    return jrpd_validate_ingress_header(buf, len, out_opcode);
}

uint32_t c_ffi_vm_exec(const uint8_t *code, size_t code_len, uint32_t gas_limit, uint64_t *out_bits) {
    jrpd_vm_exec_result_t r = jrpd_vm_execute(code, code_len, gas_limit);
    if (out_bits != NULL) *out_bits = r.result_bits;
    return (uint32_t)r.status;
}
