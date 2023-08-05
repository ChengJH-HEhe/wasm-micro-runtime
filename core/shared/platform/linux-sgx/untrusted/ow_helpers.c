/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <assert.h>
#include <time.h>

#include "Enclave_u.h"
#include "sgx_urts.h"
#include "pal_api.h"
#include "parse_key_file.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define TOKEN_FILENAME   "enclave.token"
#define ENCLAVE_FILENAME "enclave.signed.so"
#define MAX_PATH 1024

#define TEST_OCALL_API 0

static sgx_enclave_id_t g_eid = 0;

sgx_enclave_id_t
pal_get_enclave_id(void)
{
    return g_eid;
}

void
ocall_print(const char* str)
{
    printf("%s", str);
}

static char *
get_exe_path(char *path_buf, unsigned path_buf_size)
{
    ssize_t i;
    ssize_t size = readlink("/proc/self/exe",
                            path_buf, path_buf_size - 1);

    if (size < 0 || (size >= path_buf_size - 1)) {
        return NULL;
    }

    path_buf[size] = '\0';
    for (i = size - 1; i >= 0; i--) {
        if (path_buf[i] == '/') {
            path_buf[i + 1] = '\0';
            break;
        }
    }
    return path_buf;
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
static int
enclave_init(sgx_enclave_id_t *p_eid)

{
    char token_path[MAX_PATH] = { '\0' };
    char enclave_path[MAX_PATH] = { '\0' };
    const char *home_dir;
    sgx_launch_token_t token = { 0 };
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    size_t write_num, enc_file_len;
    FILE *fp;

    enc_file_len = strlen(ENCLAVE_FILENAME);
    if (!get_exe_path(enclave_path, sizeof(enclave_path) - enc_file_len)) {
        printf("Failed to get exec path\n");
        return -1;
    }
    memcpy(enclave_path + strlen(enclave_path), ENCLAVE_FILENAME, enc_file_len);

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    home_dir = getpwuid(getuid())->pw_dir;
    size_t home_dir_len = home_dir ? strlen(home_dir) : 0;

    if (home_dir != NULL &&
        home_dir_len <= MAX_PATH - 1 - sizeof(TOKEN_FILENAME) - strlen("/")) {
        /* compose the token path */
        strncpy(token_path, home_dir, MAX_PATH);
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
    }
    else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n",
               token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG,
                             &token, &updated, p_eid, NULL);
    if (ret != SGX_SUCCESS)
        /* Try to load enclave.sign.so from the path of exe file */
        ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG,
                                 &token, &updated, p_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Failed to create enclave from %s, error code: %d\n",
               ENCLAVE_FILENAME, ret);
        if (fp != NULL)
            fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL)
        return 0;

    write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);

    fclose(fp);
    return 0;
}

static unsigned char *
read_file_to_buffer(const char *filename, uint32_t *ret_size)
{
    unsigned char *buffer;
    FILE *file;
    int file_size, read_size;

    if (!filename || !ret_size) {
        printf("Read file to buffer failed: invalid filename or ret size.\n");
        return NULL;
    }

    if (!(file = fopen(filename, "r"))) {
        printf("Read file to buffer failed: open file %s failed.\n",
               filename);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (!(buffer = (unsigned char*)malloc(file_size))) {
        printf("Read file to buffer failed: alloc memory failed.\n");
        fclose(file);
        return NULL;
    }

    read_size = fread(buffer, 1, file_size, file);
    fclose(file);

    if (read_size < file_size) {
        printf("Read file to buffer failed: read file content failed.\n");
        free(buffer);
        return NULL;
    }

    *ret_size = file_size;

    return buffer;
}

static int
print_help()
{
    printf("Usage: iwasm [-options] wasm_file [args...]\n");
    printf("options:\n");
    printf("  -f|--function name     Specify a function name of the module to run rather\n"
           "                         than main\n");
    printf("  -v=n                   Set log verbose level (0 to 5, default is 2) larger\n"
           "                         level with more log\n");
    printf("  --stack-size=n         Set maximum stack size in bytes, default is 16 KB\n");
    printf("  --heap-size=n          Set maximum heap size in bytes, default is 16 KB\n");
    printf("  --repl                 Start a very simple REPL (read-eval-print-loop) mode\n"
           "                         that runs commands in the form of `FUNC ARG...`\n");
    printf("  --env=<env>            Pass wasi environment variables with \"key=value\"\n");
    printf("                         to the program, for example:\n");
    printf("                           --env=\"key1=value1\" --env=\"key2=value2\"\n");
    printf("  --dir=<dir>            Grant wasi access to the given host directories\n");
    printf("                         to the program, for example:\n");
    printf("                           --dir=<dir1> --dir=<dir2>\n");
    printf("  --max-threads=n        Set maximum thread number per cluster, default is 4\n");
    return 1;
}

/**
 * Split a space separated strings into an array of strings
 * Returns NULL on failure
 * Memory must be freed by caller
 * Based on: http://stackoverflow.com/a/11198630/471795
 */
static char **
split_string(char *str, int *count)
{
    char **res = NULL;
    char *p;
    int idx = 0;

    /* split string and append tokens to 'res' */
    do {
        p = strtok(str, " ");
        str = NULL;
        res = (char **)realloc(res, sizeof(char *) * (unsigned)(idx + 1));
        if (res == NULL) {
            return NULL;
        }
        res[idx++] = p;
    } while (p);

    /**
     * since the function name,
     * res[0] might be contains a '\' to indicate a space
     * func\name -> func name
     */
    p = strchr(res[0], '\\');
    while (p) {
        *p = ' ';
        p = strchr(p, '\\');
    }

    if (count) {
        *count = idx - 1;
    }
    return res;
}

typedef enum EcallCmd {
    CMD_INIT_RUNTIME = 0,     /* wasm_runtime_init/full_init() */
    CMD_LOAD_MODULE,          /* wasm_runtime_load() */
    CMD_INSTANTIATE_MODULE,   /* wasm_runtime_instantiate() */
    CMD_LOOKUP_FUNCTION,      /* wasm_runtime_lookup_function() */
    CMD_CREATE_EXEC_ENV,      /* wasm_runtime_create_exec_env() */
    CMD_CALL_WASM_A,          /* wasm_runtime_call_wasm_a */
    CMD_EXEC_APP_FUNC,        /* wasm_application_execute_func() */
    CMD_EXEC_APP_MAIN,        /* wasm_application_execute_main() */
    CMD_GET_EXCEPTION,        /* wasm_runtime_get_exception() */
    CMD_DEINSTANTIATE_MODULE, /* wasm_runtime_deinstantiate() */
    CMD_UNLOAD_MODULE,        /* wasm_runtime_unload() */
    CMD_DESTROY_RUNTIME,      /* wasm_runtime_destroy() */
    CMD_SET_WASI_ARGS,        /* wasm_runtime_set_wasi_args() */
    CMD_SET_LOG_LEVEL,        /* bh_log_set_verbose_level() */
    CMD_DESTROY_EXEC_ENV,     /* wasm_runtime_destroy_exec_env() */
    CMD_LOOKUP_WASI_START_FUNCTION,      /* wasm_runtime_lookup_wasi_start_function() */
    CMD_COPY_POINTER,
    CMD_COPY_TO_WASM,
} EcallCmd;

static void
app_instance_func(void *wasm_module_inst, const char *func_name,
                  int app_argc, char **app_argv);

static bool
validate_env_str(char *env)
{
    char *p = env;
    int key_len = 0;

    while (*p != '\0' && *p != '=') {
        key_len++;
        p++;
    }

    if (*p != '=' || key_len == 0)
        return false;

    return true;
}

static bool
set_log_verbose_level(int log_verbose_level)
{
    uint64_t ecall_args[1];

    /* Set log verbose level */
    if (log_verbose_level != 2) {
        ecall_args[0] = log_verbose_level;
        if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_SET_LOG_LEVEL,
                                                (uint8_t *)ecall_args,
                                                sizeof(uint64_t))) {
            printf("Call ecall_handle_command() failed.\n");
            return false;
        }
    }
    return true;
}

void *
wasm_runtime_lookup_function(void *module_inst, const char *name, const char *signature) {
    uint64_t ecall_args[3];

    ecall_args[0] = (uint64_t)module_inst;
    ecall_args[1] = (uint64_t)name;
    ecall_args[2] = (uint64_t)signature;
    if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_LOOKUP_FUNCTION,
                                            (uint8_t *)ecall_args,
                                            sizeof(uint64_t) * 3)) {
        printf("Call ecall_handle_command() failed.\n");
        return NULL;
    }
    if (!ecall_args[0]) {
        printf("Lookup WASI start function failed.\n");
        return NULL;
    }
    return (void *)(ecall_args[0]);
}

void *
wasm_runtime_lookup_wasi_start_function(void *module_inst) {
    uint64_t ecall_args[1];

    ecall_args[0] = (uint64_t)module_inst;
    if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_LOOKUP_WASI_START_FUNCTION,
                                            (uint8_t *)ecall_args,
                                            sizeof(uint64_t) * 1)) {
        printf("Call ecall_handle_command() failed.\n");
        return NULL;
    }
    if (!ecall_args[0]) {
        printf("Lookup WASI start function failed.\n");
        return NULL;
    }
    return (void *)(ecall_args[0]);
}

bool wasm_runtime_init()
{
    uint64_t ecall_args[2];

    ecall_args[0] = true;
    ecall_args[1] = 4;
    if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_INIT_RUNTIME,
                                            (uint8_t *)ecall_args,
                                            sizeof(uint64_t) * 2)) {
        printf("Call ecall_handle_command() failed.\n");
        return false;
    }
    if (!ecall_args[0]) {
        printf("Init runtime environment failed.\n");
        return false;
    }
    return (bool)(ecall_args[0]);
}

void *wasm_runtime_create_exec_env(void *module_inst, uint32_t stack_size)
{
    uint64_t ecall_args[2];

    ecall_args[0] = (uint64_t)module_inst;
    ecall_args[1] = (uint64_t)stack_size;
    if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_CREATE_EXEC_ENV,
                                            (uint8_t *)ecall_args,
                                            sizeof(uint64_t) * 2)) {
        printf("Call ecall_handle_command() failed.\n");
        return NULL;
    }
    if (!(bool)ecall_args[0]) {
        printf("Create execution environment failed.\n");
        return NULL;
    }
    return (void *)(ecall_args[0]);
}

void wasm_runtime_destroy_exec_env(void *exec_env)
{
    uint64_t ecall_args[1];

    ecall_args[0] = (uint64_t)exec_env;

    if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_DESTROY_EXEC_ENV,
                                            (uint8_t *)ecall_args, sizeof(uint64_t))) {
        printf("Call ecall_handle_command() failed.\n");
    }
}

static void *wasm_copy_pointer_buffer = NULL;
static uint64_t wasm_copy_pointer_buffer_size = 0;

void *wasm_runtime_copy_pointer(void *module_inst, uint32_t app_offset, size_t len) {
    uint64_t ecall_args[4];

    if (len > wasm_copy_pointer_buffer_size) {
        if (wasm_copy_pointer_buffer != NULL) {
            free(wasm_copy_pointer_buffer);
        }
        wasm_copy_pointer_buffer = malloc(len);
        wasm_copy_pointer_buffer_size = len;
    }

    ecall_args[0] = (uint64_t)module_inst;
    ecall_args[1] = (uint64_t)app_offset;
    ecall_args[2] = (uint64_t)len;
    ecall_args[3] = (uint64_t)wasm_copy_pointer_buffer;
    if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_COPY_POINTER,
                                            (uint8_t *)ecall_args,
                                            sizeof(uint64_t) * 4)) {
        printf("Call ecall_handle_command() failed.\n");
        return NULL;
    }
    if (!(bool)ecall_args[0]) {
        printf("Create execution environment failed.\n");
        return NULL;
    }
    return wasm_copy_pointer_buffer;
}

bool wasm_runtime_copy_to_wasm(void *module_inst, uint32_t app_offset, size_t len, const char *external_buffer) {
    uint64_t ecall_args[4];

    ecall_args[0] = (uint64_t)module_inst;
    ecall_args[1] = (uint64_t)app_offset;
    ecall_args[2] = (uint64_t)len;
    ecall_args[3] = (uint64_t)external_buffer;
    if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_COPY_TO_WASM,
                                            (uint8_t *)ecall_args,
                                            sizeof(uint64_t) * 4)) {
        printf("Call ecall_handle_command() failed.\n");
        return false;
    }
    if (!(bool)ecall_args[0]) {
        printf("Create execution environment failed.\n");
        return false;
    }
    return true;
}

bool
wasm_runtime_call_wasm_a(void *exec_env,
                         void *function,
                         uint32_t num_results, void *results,
                         uint32_t num_args, void *args) {
    uint64_t ecall_args[6];

    ecall_args[0] = (uint64_t)exec_env;
    ecall_args[1] = (uint64_t)function;
    ecall_args[2] = (uint64_t)(num_results);
    ecall_args[3] = (uint64_t)(results);
    ecall_args[4] = (uint64_t)(num_args);
    ecall_args[5] = (uint64_t)(args);

    if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_CALL_WASM_A,
                                            (uint8_t *)ecall_args, sizeof(uint64_t) * 6)) {
        printf("Call ecall_handle_command() failed.\n");
        return 0;
    }
    return (bool)(ecall_args[0]);
}

void wasm_runtime_destroy()
{
    if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_DESTROY_RUNTIME,
                                            NULL, 0)) {
        printf("Call ecall_handle_command() failed.\n");
    }
}

void *wasm_runtime_load(uint8_t *wasm_file_buf, uint32_t wasm_file_size,
            char *error_buf, uint32_t error_buf_size)
{
    uint64_t ecall_args[4];

    ecall_args[0] = (uint64_t)(uintptr_t)wasm_file_buf;
    ecall_args[1] = wasm_file_size;
    ecall_args[2] = (uint64_t)(uintptr_t)error_buf;
    ecall_args[3] = error_buf_size;
    if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_LOAD_MODULE,
                                            (uint8_t *)ecall_args,
                                            sizeof(uint64_t) * 4)) {
        printf("Call ecall_handle_command() failed.\n");
        return NULL;
    }

    return (void *)(uintptr_t)ecall_args[0];
}

void wasm_runtime_unload(void *wasm_module)
{
    uint64_t ecall_args[1];

    ecall_args[0] = (uint64_t)(uintptr_t)wasm_module;
    if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_UNLOAD_MODULE,
                                            (uint8_t *)ecall_args,
                                            sizeof(uint64_t))) {
        printf("Call ecall_handle_command() failed.\n");
    }
}

void *wasm_runtime_instantiate(void *wasm_module,
                   uint32_t stack_size, uint32_t heap_size,
                   char *error_buf, uint32_t error_buf_size)
{
    uint64_t ecall_args[5];

    ecall_args[0] = (uint64_t)(uintptr_t)wasm_module;
    ecall_args[1] = stack_size;
    ecall_args[2] = heap_size;
    ecall_args[3] = (uint64_t)(uintptr_t)error_buf;
    ecall_args[4] = error_buf_size;
    if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_INSTANTIATE_MODULE,
                                            (uint8_t *)ecall_args,
                                            sizeof(uint64_t) * 5)) {
        printf("Call ecall_handle_command() failed.\n");
        return NULL;
    }

    return (void *)(uintptr_t)ecall_args[0];
}

void wasm_runtime_deinstantiate(void *wasm_module_inst)
{
    uint64_t ecall_args[1];

    ecall_args[0] = (uint64_t)(uintptr_t)wasm_module_inst;
    if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_DEINSTANTIATE_MODULE,
                                            (uint8_t *)ecall_args,
                                            sizeof(uint64_t))) {
        printf("Call ecall_handle_command() failed.\n");
    }
}

static char wasm_runtime_exception[200];

const char *
wasm_runtime_get_exception(void *wasm_module_inst) {
    uint64_t ecall_args[3];

    ecall_args[0] = (uint64_t)(uintptr_t)wasm_module_inst;
    ecall_args[1] = (uint64_t)(uintptr_t)wasm_runtime_exception;
    ecall_args[2] = 200;
    if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_GET_EXCEPTION,
                                            (uint8_t *)ecall_args,
                                            sizeof(uint64_t) * 3)) {
        printf("Call ecall_handle_command() failed.\n");
    }

    return (const char*)wasm_runtime_exception;
}

bool wasm_runtime_set_wasi_args(void *wasm_module,
              const char **dir_list, uint32_t dir_list_size,
              const char **env_list, uint32_t env_list_size,
              int stdinfd, int stdoutfd, int stderrfd,
              char **argv, uint32_t argc)
{
    uint64_t ecall_args[10];

    ecall_args[0] = (uint64_t)(uintptr_t)wasm_module;
    ecall_args[1] = (uint64_t)(uintptr_t)dir_list;
    ecall_args[2] = dir_list_size;
    ecall_args[3] = (uint64_t)(uintptr_t)env_list;
    ecall_args[4] = env_list_size;
    ecall_args[5] = stdinfd;
    ecall_args[6] = stdoutfd;
    ecall_args[7] = stderrfd;
    ecall_args[8] = (uint64_t)(uintptr_t)argv;
    ecall_args[9] = argc;
    if (SGX_SUCCESS != ecall_handle_command(g_eid, CMD_SET_WASI_ARGS,
                                            (uint8_t *)ecall_args,
                                            sizeof(uint64_t) * 10)) {
        printf("Call ecall_handle_command() failed.\n");
    }

    return (bool)ecall_args[0];
}

uint64_t
time_diff(struct timespec *ts1, struct timespec *ts2) {
    uint64_t t1;
    uint64_t t2;

    t1 = ts1->tv_sec * 1000000000 + ts1->tv_nsec;
    t2 = ts2->tv_sec * 1000000000 + ts2->tv_nsec;
    return t2 - t1;
}

uint64_t ocall_rdtsc() {
    uint32_t low, high;
    asm volatile (
        "rdtsc"
	: "=a"(low), "=d"(high)
    );
    return (((uint64_t)high) << 32) | low;
}

int (*http_get)(void *ptr) = NULL;

int ocall_http_get(void *ptr) {
    if (http_get == NULL) {
        return -1;
    }
    return (*http_get)(ptr);
}

void wamr_set_http_get(void *ptr) {
    http_get = ptr;
}

extern int run_server();
int wasm_enter_dcap_server() {
    return run_server();
}

extern sgx_enclave_id_t e2_enclave_id;

int enclave_setup() {
    struct timespec ts1;
    struct timespec ts2;

    //clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts1);

    if (enclave_init(&g_eid) < 0) {
        printf("Failed to initialise enclave\n");
        return -1;
    }

    e2_enclave_id = g_eid;

    //clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts2);
    //printf("DEBUG: enclave_init took %ld\n", time_diff(&ts1, &ts2));
    

    return 0;
}

void enclave_post_attestation() {
    int dummy;
    
    rsa_params_t rsa_params;
    int key_type;
    
    
    printf("Enter 1 after attestation...\n");
    scanf("%d", &dummy);
    
#ifdef NSKERNEL_USE_RSA
    printf("DEBUG: Attestation using RSA\n");
    printf("DEBUG: Parsing private key...\n");
    if (!parse_key_file("enclave_private_test_key.pem", &rsa_params, &key_type)) {
        printf("Failed to parse key\n");
        return -1;
    }
    rsa_params.e[0] = 3;
    
    sgx_rsa3072_key_t rsa_key;
    memcpy(&(rsa_key.mod), &(rsa_params.n), sizeof(rsa_key.mod));
    memcpy(&(rsa_key.d), &(rsa_params.d), sizeof(rsa_key.d));
    memcpy(&(rsa_key.e), &(rsa_params.e), sizeof(rsa_key.e));
    ecall_nskernel_set_key(g_eid, &rsa_key);
#endif
    
#ifdef NSKERNEL_USE_ECDSA
    printf("DEBUG: Attestation using ECDSA\n");
    ecall_nskernel_generate_ecdsa_key(g_eid);
#endif

#ifdef NSKERNEL_USE_AES
    printf("DEBUG: Attestation using AES\n");
#endif
    
    ecall_nskernel_snapshot(g_eid);
    printf("DEBUG: snapshot\n");
}

int enclave_destroy() {
    struct timespec ts1;
    struct timespec ts2;

    //clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts1);
    sgx_destroy_enclave(g_eid);
    //clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts2);
    //printf("DEBUG: enclave destroy took %ld\n", time_diff(&ts1, &ts2));
}


int enclave_reset() {
    ecall_nskernel_rollback(g_eid);
}

