/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WASM_EXPORT_H
#define _WASM_EXPORT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "lib_export.h"


#ifndef WASM_RUNTIME_API_EXTERN
#if defined(_MSC_BUILD )
    #if defined(COMPILING_WASM_RUNTIME_API)
        #define WASM_RUNTIME_API_EXTERN __declspec(dllexport)
    #else
        #define WASM_RUNTIME_API_EXTERN __declspec(dllimport)
    #endif
#else
#define WASM_RUNTIME_API_EXTERN
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define get_module_inst(exec_env) \
    wasm_runtime_get_module_inst(exec_env)

#define validate_app_addr(offset, size) \
    wasm_runtime_validate_app_addr(module_inst, offset, size)

#define validate_app_str_addr(offset) \
    wasm_runtime_validate_app_str_addr(module_inst, offset)

#define addr_app_to_native(offset) \
    wasm_runtime_addr_app_to_native(module_inst, offset)

#define addr_native_to_app(ptr) \
    wasm_runtime_addr_native_to_app(module_inst, ptr)

#define module_malloc(size, p_native_addr) \
    wasm_runtime_module_malloc(module_inst, size, p_native_addr)

#define module_free(offset) \
    wasm_runtime_module_free(module_inst, offset)

#define native_raw_return_type(type, args) type *raw_ret = (type*)(args)

#define native_raw_get_arg(type, name, args) type name = *((type*)(args++))

#define native_raw_set_return(val) *raw_ret = (val)


#ifndef WASM_MODULE_T_DEFINED
#define WASM_MODULE_T_DEFINED
/* Uninstantiated WASM module loaded from WASM binary file
   or AoT binary file*/
struct WASMModuleCommon;
typedef struct WASMModuleCommon *wasm_module_t;
#endif

/* Instantiated WASM module */
struct WASMModuleInstanceCommon;
typedef struct WASMModuleInstanceCommon *wasm_module_inst_t;

/* Function instance */
typedef void WASMFunctionInstanceCommon;
typedef WASMFunctionInstanceCommon *wasm_function_inst_t;

/* WASM section */
typedef struct wasm_section_t {
    struct wasm_section_t *next;
    /* section type */
    int section_type;
    /* section body, not include type and size */
    uint8_t *section_body;
    /* section body size */
    uint32_t section_body_size;
} wasm_section_t, aot_section_t, *wasm_section_list_t, *aot_section_list_t;

/* Execution environment, e.g. stack info */
struct WASMExecEnv;
typedef struct WASMExecEnv *wasm_exec_env_t;

/* Package Type */
typedef enum {
    Wasm_Module_Bytecode = 0,
    Wasm_Module_AoT,
    Package_Type_Unknown = 0xFFFF
} package_type_t;

#ifndef MEM_ALLOC_OPTION_DEFINED
#define MEM_ALLOC_OPTION_DEFINED
/* Memory allocator type */
typedef enum {
    /* pool mode, allocate memory from user defined heap buffer */
    Alloc_With_Pool = 0,
    /* user allocator mode, allocate memory from user defined
       malloc function */
    Alloc_With_Allocator,
    /* system allocator mode, allocate memory from system allocator,
       or, platform's os_malloc function */
    Alloc_With_System_Allocator,
} mem_alloc_type_t;

/* Memory allocator option */
typedef union MemAllocOption {
    struct {
        void *heap_buf;
        uint32_t heap_size;
    } pool;
    struct {
        void *malloc_func;
        void *realloc_func;
        void *free_func;
    } allocator;
} MemAllocOption;
#endif

/* WASM runtime initialize arguments */
typedef struct RuntimeInitArgs {
    mem_alloc_type_t mem_alloc_type;
    MemAllocOption mem_alloc_option;

    const char *native_module_name;
    NativeSymbol *native_symbols;
    uint32_t n_native_symbols;

    /* maximum thread number, only used when
        WASM_ENABLE_THREAD_MGR is defined */
    uint32_t max_thread_num;
} RuntimeInitArgs;

#ifndef WASM_VALKIND_T_DEFINED
#define WASM_VALKIND_T_DEFINED
typedef uint8_t wasm_valkind_t;
enum wasm_valkind_enum {
    WASM_I32,
    WASM_I64,
    WASM_F32,
    WASM_F64,
    WASM_ANYREF = 128,
    WASM_FUNCREF,
};
#endif

#ifndef WASM_VAL_T_DEFINED
#define WASM_VAL_T_DEFINED
struct wasm_ref_t;

typedef struct wasm_val_t {
  wasm_valkind_t kind;
  union {
    int32_t i32;
    int64_t i64;
    float f32;
    double f64;
    struct wasm_ref_t* ref;
  } of;
} wasm_val_t;
#endif

/**
 * Initialize the WASM runtime environment, and also initialize
 * the memory allocator with system allocator, which calls os_malloc
 * to allocate memory
 *
 * @return true if success, false otherwise
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_init(void);

/**
 * Destroy the WASM runtime environment.
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_destroy(void);

/**
 * Load a WASM module from a specified byte buffer. The byte buffer can be
 * WASM binary data when interpreter or JIT is enabled, or AOT binary data
 * when AOT is enabled. If it is AOT binary data, it must be 4-byte aligned.
 *
 * @param buf the byte buffer which contains the WASM binary data
 * @param size the size of the buffer
 * @param error_buf output of the exception info
 * @param error_buf_size the size of the exception string
 *
 * @return return WASM module loaded, NULL if failed
 */
WASM_RUNTIME_API_EXTERN wasm_module_t
wasm_runtime_load(const uint8_t *buf, uint32_t size,
                  char *error_buf, uint32_t error_buf_size);

/**
 * Load a WASM module from a specified WASM or AOT section list.
 *
 * @param section_list the section list which contains each section data
 * @param is_aot whether the section list is AOT section list
 * @param error_buf output of the exception info
 * @param error_buf_size the size of the exception string
 *
 * @return return WASM module loaded, NULL if failed
 */
WASM_RUNTIME_API_EXTERN wasm_module_t
wasm_runtime_load_from_sections(wasm_section_list_t section_list, bool is_aot,
                                char *error_buf, uint32_t error_buf_size);

/**
 * Unload a WASM module.
 *
 * @param module the module to be unloaded
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_unload(wasm_module_t module);

//WASM_RUNTIME_API_EXTERN void
//wasm_runtime_set_wasi_args(wasm_module_t module,
//                           const char *dir_list[], uint32_t dir_count,
//                           const char *map_dir_list[], uint32_t map_dir_count,
//                           const char *env[], uint32_t env_count,
//                           char *argv[], int argc);

bool wasm_runtime_set_wasi_args(wasm_module_t wasm_module,
              const char **dir_list, uint32_t dir_list_size,
              const char **env_list, uint32_t env_list_size,
              int stdinfd, int stdoutfd, int stderrfd,
              char **argv, uint32_t argc);

/**
 * Instantiate a WASM module.
 *
 * @param module the WASM module to instantiate
 * @param stack_size the default stack size of the module instance when the
 *        exec env's operation stack isn't created by user, e.g. API
 *        wasm_application_execute_main() and wasm_application_execute_func()
 *        create the operation stack internally with the stack size specified
 *        here. And API wasm_runtime_create_exec_env() creates the operation
 *        stack with stack size specified by its parameter, the stack size
 *        specified here is ignored.
 * @param heap_size the default heap size of the module instance, a heap will
 *        be created besides the app memory space. Both wasm app and native
 *        function can allocate memory from the heap.
 * @param error_buf buffer to output the error info if failed
 * @param error_buf_size the size of the error buffer
 *
 * @return return the instantiated WASM module instance, NULL if failed
 */
WASM_RUNTIME_API_EXTERN wasm_module_inst_t
wasm_runtime_instantiate(const wasm_module_t module,
                         uint32_t stack_size, uint32_t heap_size,
                         char *error_buf, uint32_t error_buf_size);

/**
 * Deinstantiate a WASM module instance, destroy the resources.
 *
 * @param module_inst the WASM module instance to destroy
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_deinstantiate(wasm_module_inst_t module_inst);

WASM_RUNTIME_API_EXTERN wasm_function_inst_t
wasm_runtime_lookup_wasi_start_function(wasm_module_inst_t module_inst);

/**
 * Lookup an exported function in the WASM module instance.
 *
 * @param module_inst the module instance
 * @param name the name of the function
 * @param signature the signature of the function, ignored currently
 *
 * @return the function instance found, NULL if not found
 */
WASM_RUNTIME_API_EXTERN wasm_function_inst_t
wasm_runtime_lookup_function(wasm_module_inst_t const module_inst,
                             const char *name, const char *signature);

/**
 * Create execution environment for a WASM module instance.
 *
 * @param module_inst the module instance
 * @param stack_size the stack size to execute a WASM function
 *
 * @return the execution environment, NULL if failed, e.g. invalid
 *         stack size is passed
 */
WASM_RUNTIME_API_EXTERN wasm_exec_env_t
wasm_runtime_create_exec_env(wasm_module_inst_t module_inst,
                             uint32_t stack_size);

/**
 * Destroy the execution environment.
 *
 * @param exec_env the execution environment to destroy
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_destroy_exec_env(wasm_exec_env_t exec_env);

/**
 * Call the given WASM function of a WASM module instance with
 * provided results space and arguments (bytecode and AoT).
 *
 * @param exec_env the execution environment to call the function,
 *   which must be created from wasm_create_exec_env()
 * @param function the function to call
 * @param num_results the number of results
 * @param results the pre-alloced pointer to get the results
 * @param num_args the number of arguments
 * @param args the arguments
 *
 * @return true if success, false otherwise and exception will be thrown,
 *   the caller can call wasm_runtime_get_exception to get the exception
 *   info.
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_call_wasm_a(wasm_exec_env_t exec_env,
                         wasm_function_inst_t function,
                         uint32_t num_results, wasm_val_t results[],
                         uint32_t num_args, wasm_val_t *args);

/**
 * Get exception info of the WASM module instance.
 *
 * @param module_inst the WASM module instance
 *
 * @return the exception string
 */
WASM_RUNTIME_API_EXTERN const char *
wasm_runtime_get_exception(wasm_module_inst_t module_inst);

WASM_RUNTIME_API_EXTERN void *
wasm_runtime_copy_pointer(wasm_module_inst_t module_inst, uint32_t app_offset, size_t len);

WASM_RUNTIME_API_EXTERN bool 
wasm_runtime_copy_to_wasm(wasm_module_inst_t module_inst, 
                          uint32_t app_offset, 
                          size_t len, 
                          const uint8_t *external_buffer);
                          
void wamr_set_http_get(void *ptr);

int enclave_setup(void);
void enclave_post_attestation(void);
int enclave_destroy(void);
int enclave_reset(void);
int run_server(void);

#ifdef __cplusplus
}
#endif

#endif /* end of _WASM_EXPORT_H */
