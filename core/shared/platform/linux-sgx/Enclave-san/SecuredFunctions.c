#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>

#include "ippcp.h"
#include "sgx_tcrypto.h"

#include "Enclave_t.h"
#include "r15_protection.h"


extern void *get_heap_base(void);
extern size_t get_heap_size(void);

extern char __data_start;
extern char _edata;

extern char __bss_start;
extern char __bss_end;

extern char __tbss_start;
extern char __tbss_end;


static char data_seg_bkp[12288] __attribute__((section(".nskernel.databk")));

int printf(const char *, ...);

void *nskernel_fast_memset(void *s, int c, size_t n);

static void __attribute__((section(".nskernel.rollbk"))) nskernel_stosb_bzero(void *addr, uint64_t size) {
	//printf("addr = 0x%016llX, size = %lld\n", (uint64_t)addr, size);
	
	// Need system-level access for low-level memory operations
	__unsan_layer2_enter();
	asm (
	    "rep stosb"
	    :
	    : "a"(0), "D"(addr), "c"(size)
	    : "memory"
	);
	__unsan_layer_exit();
}

#include "HeapInfo.h"

extern char global_heap_buf[];

static void __attribute__((section(".nskernel.rollbk"))) __unsan_nskernel_reset_heap() {
	// This is an unaligned critical function, but still needs boundary access for heap operations
	//nskernel_fast_memset(global_heap_buf, 0, _WASM_HEAP_SIZE);
}

static void __attribute__((section(".nskernel.rollbk"))) nskernel_reset_bss() {
	size_t bss_seg_size = (uint64_t)&__bss_end - (uint64_t)&__bss_start;
	
	// Need system-level access for BSS segment reset
	__unsan_layer2_enter();
	bzero(&__bss_start, bss_seg_size);
	__unsan_layer_exit();
}

static void __attribute__((section(".nskernel.rollbk"))) nskernel_reset_tbss() {
	size_t tbss_seg_size = (uint64_t)&__tbss_end - (uint64_t)&__tbss_start;
	
	// Need system-level access for TBSS segment reset
	__unsan_layer2_enter();
	bzero(&__tbss_start, tbss_seg_size);
	__unsan_layer_exit();
}

void __attribute__((section(".nskernel.rollbk"))) nskernel_take_snapshot() {
	size_t data_seg_size = (uint64_t)&_edata - (uint64_t)&__data_start;
	
	// Need system-level access for data segment backup
	__unsan_layer2_enter();
	memcpy(data_seg_bkp, &__data_start, data_seg_size);
	__unsan_layer_exit();
}

static void __attribute__((section(".nskernel.rollbk"))) nskernel_rollback_data() {
	size_t data_seg_size = (uint64_t)&_edata - (uint64_t)&__data_start;
	
	// Need system-level access for data segment restoration
	__unsan_layer2_enter();
	memcpy(&__data_start, data_seg_bkp, data_seg_size);
	__unsan_layer_exit();
}

void __attribute__((section(".nskernel.rollbk"))) __unsan_nskernel_rollback() {
	// Internal unaligned critical function - no independent boundary management
	nskernel_rollback_data();
	__unsan_nskernel_reset_heap();
	nskernel_reset_bss();
}

void enclave_print(const char *message);

void __attribute__((section(".nskernel.rollbk"))) nskernel_rollback() { 
        //enclave_print("Bypassing for CPP\n");
        __unsan_nskernel_rollback();
}
extern char outside_print_buffer[100];
static uint8_t data_backup_hash[SGX_SHA256_HASH_SIZE];
static uint8_t data_backup_hash_buffer[SGX_SHA256_HASH_SIZE];

#ifdef NSKERNEL_USE_RSA
static sgx_rsa3072_key_t sign_rsa_key;
void __attribute__((section(".nskernel.attest"))) ecall_nskernel_set_key(void *key) {
	__unsan_layer1_enter();
	
	memcpy(&sign_rsa_key, key, sizeof(sgx_rsa3072_key_t));
	
	__unsan_layer_exit();
}
#else
void __attribute__((section(".nskernel.attest"))) ecall_nskernel_set_key(void *key) {
	__unsan_layer1_enter();
	__unsan_layer_exit();
}
#endif

#ifdef NSKERNEL_USE_ECDSA
sgx_ec256_private_t ecdsa_private_key;
sgx_ec256_public_t ecdsa_public_key;
void ecall_nskernel_generate_ecdsa_key(void) {
	__unsan_layer1_enter();
	
	sgx_ecc_state_handle_t ecc_state = NULL;
	sgx_status_t se_ret;
	
	se_ret = sgx_ecc256_open_context(&ecc_state);
	if(se_ret != SGX_SUCCESS) {
		enclave_print("ECDSA Key Gen: Failed to open ECC256 context\n");
		__unsan_layer_exit();
		return;
	}
	se_ret = sgx_ecc256_create_key_pair(&ecdsa_private_key, &ecdsa_public_key, ecc_state);
	if(se_ret != SGX_SUCCESS) {
		enclave_print("ECDSA Key Gen: Failed to create key pair\n");
	}
	sgx_ecc256_close_context(ecc_state);
	
	__unsan_layer_exit();
}
#else
void ecall_nskernel_generate_ecdsa_key(void) {
	__unsan_layer1_enter();
	__unsan_layer_exit();
}
#endif

uint8_t __attribute__((section(".nskernel.attest"))) *nskernel_hash_data_backup(void) {
	__unsan_layer1_enter();
	
	IppStatus ipp_ret;
	sgx_sha_state_handle_t sha_context;
	sgx_sha256_hash_t hash_result;
	
	IppsHashState_rmf *p_temp_state = NULL;
	
	int ctx_size = 0;
	ipp_ret = ippsHashGetSize_rmf(&ctx_size);
	if (ipp_ret != ippStsNoErr) {
		enclave_print("SHA256: IPP: Failed to get size\n");
		__unsan_layer_exit();
		return NULL;
	}
	// TODO: Replace malloc with protected heap
	p_temp_state = (IppsHashState_rmf *)(malloc(ctx_size));
	//snprintf(outside_print_buffer, 100, "DEBUG: ctx_size = %d\n", ctx_size);
	//enclave_print(outside_print_buffer);
	if (p_temp_state == NULL) {
		enclave_print("SHA256: IPP: Failed to allocate state\n");
		__unsan_layer_exit();
		return NULL;
	}
	ipp_ret = ippsHashInit_rmf(p_temp_state, ippsHashMethod_SHA256_TT());
	if (ipp_ret != ippStsNoErr) {
		// TODO: Replace SAFE_FREE
		free(p_temp_state);
		enclave_print("SHA256: IPP: Failed to init hash\n");
		__unsan_layer_exit();
		return NULL;
	}
	sha_context = p_temp_state;
	
	if (sgx_sha256_update((uint8_t *)data_seg_bkp, 12288, sha_context) != SGX_SUCCESS) {
		free(p_temp_state);
		enclave_print("SHA256: Failed to update SHA256\n");
		__unsan_layer_exit();
		return NULL;
	}
	
	if (sgx_sha256_get_hash(sha_context, &hash_result) != SGX_SUCCESS) {
		free(p_temp_state);
		enclave_print("SHA256: Failed to get SHA256 hash\n");
		__unsan_layer_exit();
		return NULL;
	}
	
	free(p_temp_state);
	/*for (int i = 0; i < SGX_SHA256_HASH_SIZE; i++) {
		snprintf(outside_print_buffer, 100, "%02X", ((uint8_t *)hash_result)[i]);
		enclave_print(outside_print_buffer);
	}
	enclave_print("\n");*/
	
	memcpy(&hash_result, data_backup_hash_buffer, SGX_SHA256_HASH_SIZE);
	
	__unsan_layer_exit();
	return (uint8_t *)data_backup_hash_buffer;
}

struct nskernel_report {
	uint8_t hash[SGX_SHA256_HASH_SIZE];
	uint8_t data[64];
};

//#define NSKERNEL_USE_RSA
//#define NSKERNEL_USE_AES

#ifdef NSKERNEL_USE_AES
sgx_aes_gcm_128bit_key_t aes_key = "NSKERNEL AESKEY";
uint8_t aes_iv[SGX_AESGCM_IV_SIZE] = { 0 };
#endif

int __attribute__((section(".nskernel.attest"))) ecall_nskernel_generate_report(uint8_t *data, uint8_t *outside_report, uint8_t *signature) {
	__unsan_layer1_enter();
	
	uint8_t *hash_buffer;
	struct nskernel_report report;
	
	hash_buffer = nskernel_hash_data_backup();
	memcpy(report.hash, hash_buffer, SGX_SHA256_HASH_SIZE);
	memcpy(report.data, data, 64);

#ifdef NSKERNEL_USE_RSA	
	sgx_status_t res = sgx_rsa3072_sign((const uint8_t*)&report, sizeof(struct nskernel_report), &sign_rsa_key, (sgx_rsa3072_signature_t *)signature);

	if (res != SGX_SUCCESS) {
		enclave_print("Failed to sign. Returned ");
		snprintf(outside_print_buffer, 100, "%d\n", res);
		enclave_print(outside_print_buffer);
		__unsan_layer_exit();
		return -1;
	}
	
	memcpy(outside_report, &report, sizeof(struct nskernel_report));
#endif
#ifdef NSKERNEL_USE_AES
	sgx_status_t res = sgx_rijndael128GCM_encrypt(&aes_key, (const uint8_t *)&report, sizeof(struct nskernel_report), outside_report, (const uint8_t *)&aes_iv, SGX_AESGCM_IV_SIZE, NULL, 0, (sgx_aes_gcm_128bit_tag_t *)signature);
	
	if (res != SGX_SUCCESS) {
		enclave_print("Failed to sign. Returned ");
		snprintf(outside_print_buffer, 100, "%d\n", res);
		enclave_print(outside_print_buffer);
		__unsan_layer_exit();
		return -1;
	}
#endif
#ifdef NSKERNEL_USE_ECDSA
	sgx_ecc_state_handle_t handle = NULL;
	
	sgx_status_t res = sgx_ecc256_open_context(&handle);
	if (res != SGX_SUCCESS) {
		enclave_print("Failed to open ECC256 context. Returned ");
		snprintf(outside_print_buffer, 100, "%d\n", res);
		enclave_print(outside_print_buffer);
		__unsan_layer_exit();
		return -1;
	}
	res = sgx_ecdsa_sign((const uint8_t *)&report, sizeof(struct nskernel_report), (const sgx_ec256_private_t *)&ecdsa_private_key, (sgx_ec256_signature_t *)signature, handle);
	if (res != SGX_SUCCESS) {
		enclave_print("Failed to sign. Returned ");
		snprintf(outside_print_buffer, 100, "%d\n", res);
		enclave_print(outside_print_buffer);
		__unsan_layer_exit();
		return -1;
	}
	sgx_ecc256_close_context(handle);
	memcpy(outside_report, &report, sizeof(struct nskernel_report));
#endif	
	
	__unsan_layer_exit();
	return 0;
}