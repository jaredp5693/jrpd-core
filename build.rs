fn main() {
    println!("cargo:rerun-if-changed=include/jrpd_opcodes.h");
    println!("cargo:rerun-if-changed=include/jrpd_vm_isa.h");
    println!("cargo:rerun-if-changed=tests/c_shim.c");

    if std::path::Path::new("tests/c_shim.c").exists() {
        cc::Build::new()
            .file("tests/c_shim.c")
            .include("include")
            .std("c11")
            .warnings(true)
            .extra_warnings(true)
            .warnings_into_errors(true)
            .compile("jrpd_c_ref");
    }
}
