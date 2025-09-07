#ifndef ENCLAVE_FUNCTION_LAYERS_H
#define ENCLAVE_FUNCTION_LAYERS_H

/*
 * Enclave Function Layer Classification
 * 
 * Based on the multi-layer compartmentalisation technique:
 * - Layer 1 (Highest Security): Attestation code and critical secrets (.attest, .cdata)
 * - Layer 2 (Medium Security): Reset module and snapshot (.reset, .snapst)  
 * - Layer 3 (Lowest Security): Regular code and data (.text, etc.)
 * 
 * The higher the security level, the lower in the address space it will be placed.
 */

/* Layer 1: Attestation and Critical Security Functions */
#define LAYER1_FUNCTIONS \
    verify_peer_enclave_trust, \
    ecall_nskernel_set_key, \
    nskernel_hash_data_backup, \
    ecall_nskernel_generate_report, \
    __unsan_memcpy

/* Layer 2: Reset Module and Snapshot Functions */
#define LAYER2_FUNCTIONS \
    ecall_handle_command, \
    ecall_iwasm_main, \
    ecall_nskernel_snapshot, \
    ecall_nskernel_rollback, \
    ecall_nskernel_generate_ecdsa_key

/* Layer 2 Internal Functions (no automatic protection, manual boundary adjustment) */
#define LAYER2_INTERNAL_FUNCTIONS \
    handle_cmd_init_runtime, \
    handle_cmd_load_module, \
    nskernel_take_snapshot, \
    nskernel_rollback, \
    __unsan_nskernel_rollback, \
    nskernel_rollback_data, \
    nskernel_reset_bss, \
    nskernel_reset_tbss, \
    __unsan_nskernel_reset_heap, \
    nskernel_stosb_bzero

/* System-level memory operations (manual protection required) */
#define SYSTEM_MEMORY_FUNCTIONS \
    memcpy, \
    memset, \
    memset_s

/* Layer 3: Regular Application Code */
#define LAYER3_FUNCTIONS \
    enclave_print, \
    printf, \
    set_error_buf, \
    handle_cmd_lookup_function, \
    handle_cmd_copy_pointer, \
    handle_cmd_copy_to_wasm, \
    handle_cmd_lookup_wasi_start_function, \
    handle_cmd_create_exec_env, \
    handle_cmd_destroy_exec_env, \
    handle_cmd_call_wasm_a, \
    handle_cmd_destroy_runtime, \
    handle_cmd_unload_module, \
    handle_cmd_instantiate_module, \
    handle_cmd_deinstantiate_module, \
    handle_cmd_get_exception, \
    handle_cmd_exec_app_main, \
    handle_cmd_exec_app_func, \
    handle_cmd_set_log_level, \
    handle_cmd_set_wasi_args

/* Function-to-Layer Mapping Macros */
#define GET_FUNCTION_LAYER(func_name) GET_FUNCTION_LAYER_##func_name

/* Layer 1 Function Mappings */
#define GET_FUNCTION_LAYER_verify_peer_enclave_trust 1
#define GET_FUNCTION_LAYER_ecall_nskernel_set_key 1
#define GET_FUNCTION_LAYER_nskernel_hash_data_backup 1
#define GET_FUNCTION_LAYER_ecall_nskernel_generate_report 1
#define GET_FUNCTION_LAYER___unsan_memcpy 1

/* Layer 2 Function Mappings */
#define GET_FUNCTION_LAYER_ecall_handle_command 2
#define GET_FUNCTION_LAYER_ecall_iwasm_main 2
#define GET_FUNCTION_LAYER_ecall_nskernel_snapshot 2
#define GET_FUNCTION_LAYER_ecall_nskernel_rollback 2
#define GET_FUNCTION_LAYER_handle_cmd_init_runtime 2
#define GET_FUNCTION_LAYER_handle_cmd_load_module 2
#define GET_FUNCTION_LAYER_nskernel_take_snapshot 2
#define GET_FUNCTION_LAYER_nskernel_rollback 2
#define GET_FUNCTION_LAYER___unsan_nskernel_rollback 2
#define GET_FUNCTION_LAYER_ecall_nskernel_generate_ecdsa_key 2
#define GET_FUNCTION_LAYER_memcpy 2
#define GET_FUNCTION_LAYER_memset 2
#define GET_FUNCTION_LAYER_memset_s 2

/* Layer 3 Function Mappings */
#define GET_FUNCTION_LAYER_enclave_print 3
#define GET_FUNCTION_LAYER_printf 3
#define GET_FUNCTION_LAYER_set_error_buf 3
#define GET_FUNCTION_LAYER_handle_cmd_lookup_function 3
#define GET_FUNCTION_LAYER_handle_cmd_copy_pointer 3
#define GET_FUNCTION_LAYER_handle_cmd_copy_to_wasm 3
#define GET_FUNCTION_LAYER_handle_cmd_lookup_wasi_start_function 3
#define GET_FUNCTION_LAYER_handle_cmd_create_exec_env 3
#define GET_FUNCTION_LAYER_handle_cmd_destroy_exec_env 3
#define GET_FUNCTION_LAYER_handle_cmd_call_wasm_a 3
#define GET_FUNCTION_LAYER_handle_cmd_destroy_runtime 3
#define GET_FUNCTION_LAYER_handle_cmd_unload_module 3
#define GET_FUNCTION_LAYER_handle_cmd_instantiate_module 3
#define GET_FUNCTION_LAYER_handle_cmd_deinstantiate_module 3
#define GET_FUNCTION_LAYER_handle_cmd_get_exception 3
#define GET_FUNCTION_LAYER_handle_cmd_exec_app_main 3
#define GET_FUNCTION_LAYER_handle_cmd_exec_app_func 3
#define GET_FUNCTION_LAYER_handle_cmd_set_log_level 3
#define GET_FUNCTION_LAYER_handle_cmd_set_wasi_args 3

/* Layer Protection Convenience Macros */
#define APPLY_LAYER_PROTECTION(func_name) \
    do { \
        int layer = GET_FUNCTION_LAYER(func_name); \
        if (layer == 1) { \
            __unsan_layer1_enter(); \
        } else if (layer == 2) { \
            __unsan_layer2_enter(); \
        } else if (layer == 3) { \
            __unsan_layer3_enter(); \
        } \
    } while(0)


/* Security Level Definitions */
typedef enum {
    SECURITY_LAYER_1 = 1,  /* Attestation and critical secrets */
    SECURITY_LAYER_2 = 2,  /* Reset module and snapshot */
    SECURITY_LAYER_3 = 3   /* Regular application code */
} security_layer_t;

/* Function Classification Structure */
typedef struct {
    const char* function_name;
    security_layer_t layer;
    const char* description;
} function_layer_mapping_t;

/* Static function layer mapping table */
static const function_layer_mapping_t function_layers[] = {
    /* Layer 1: Attestation and Critical Security */
    {"verify_peer_enclave_trust", SECURITY_LAYER_1, "Peer enclave identity verification"},
    {"ecall_nskernel_set_key", SECURITY_LAYER_1, "NSKernel cryptographic key setting"},
    {"nskernel_hash_data_backup", SECURITY_LAYER_1, "Data backup hash generation"},
    {"ecall_nskernel_generate_report", SECURITY_LAYER_1, "Attestation report generation"},
    
    /* Layer 2: Reset Module and Snapshot */
    {"ecall_handle_command", SECURITY_LAYER_2, "Main ecall command dispatcher"},
    {"ecall_iwasm_main", SECURITY_LAYER_2, "WASM main entry point"},
    {"ecall_nskernel_snapshot", SECURITY_LAYER_2, "NSKernel snapshot operation"},
    {"ecall_nskernel_rollback", SECURITY_LAYER_2, "NSKernel rollback operation"},
    {"handle_cmd_init_runtime", SECURITY_LAYER_2, "Runtime initialization with memory management"},
    {"handle_cmd_load_module", SECURITY_LAYER_2, "Module loading with decryption"},
    {"nskernel_take_snapshot", SECURITY_LAYER_2, "Internal snapshot taking"},
    {"nskernel_rollback", SECURITY_LAYER_2, "Internal rollback operation"},
    {"__unsan_nskernel_rollback", SECURITY_LAYER_2, "Unsanitized rollback operation"},
    {"ecall_nskernel_generate_ecdsa_key", SECURITY_LAYER_2, "ECDSA key generation"},
    
    /* Layer 3: Regular Application Code */
    {"enclave_print", SECURITY_LAYER_3, "Debug output function"},
    {"printf", SECURITY_LAYER_3, "Formatted output function"},
    {"set_error_buf", SECURITY_LAYER_3, "Error message setting"},
    {"handle_cmd_lookup_function", SECURITY_LAYER_3, "WASM function lookup"},
    {"handle_cmd_copy_pointer", SECURITY_LAYER_3, "Memory copy from WASM"},
    {"handle_cmd_copy_to_wasm", SECURITY_LAYER_3, "Memory copy to WASM"},
    {"handle_cmd_lookup_wasi_start_function", SECURITY_LAYER_3, "WASI start function lookup"},
    {"handle_cmd_create_exec_env", SECURITY_LAYER_3, "Execution environment creation"},
    {"handle_cmd_destroy_exec_env", SECURITY_LAYER_3, "Execution environment destruction"},
    {"handle_cmd_call_wasm_a", SECURITY_LAYER_3, "WASM function call"},
    {"handle_cmd_destroy_runtime", SECURITY_LAYER_3, "Runtime destruction"},
    {"handle_cmd_unload_module", SECURITY_LAYER_3, "Module unloading"},
    {"handle_cmd_instantiate_module", SECURITY_LAYER_3, "Module instantiation"},
    {"handle_cmd_deinstantiate_module", SECURITY_LAYER_3, "Module deinstantiation"},
    {"handle_cmd_get_exception", SECURITY_LAYER_3, "Exception information retrieval"},
    {"handle_cmd_exec_app_main", SECURITY_LAYER_3, "Application main execution"},
    {"handle_cmd_exec_app_func", SECURITY_LAYER_3, "Application function execution"},
    {"handle_cmd_set_log_level", SECURITY_LAYER_3, "Log level setting"},
    {"handle_cmd_set_wasi_args", SECURITY_LAYER_3, "WASI arguments setting"},
    {NULL, 0, NULL} /* Sentinel */
};

#endif /* ENCLAVE_FUNCTION_LAYERS_H */
