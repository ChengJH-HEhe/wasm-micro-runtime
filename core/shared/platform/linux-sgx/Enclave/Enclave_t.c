#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_handle_command_t {
	unsigned int ms_cmd;
	uint8_t* ms_cmd_buf;
	unsigned int ms_cmd_buf_size;
} ms_ecall_handle_command_t;

typedef struct ms_ecall_iwasm_main_t {
	uint8_t* ms_wasm_file_buf;
	uint32_t ms_wasm_file_size;
} ms_ecall_iwasm_main_t;

typedef struct ms_ecall_nskernel_set_key_t {
	void* ms_key;
} ms_ecall_nskernel_set_key_t;

typedef struct ms_ecall_nskernel_generate_report_t {
	int ms_retval;
	uint8_t* ms_data;
	uint8_t* ms_report;
	uint8_t* ms_signature;
} ms_ecall_nskernel_generate_report_t;

typedef struct ms_session_request_t {
	uint32_t ms_retval;
	sgx_dh_dcap_msg1_t* ms_dh_msg1;
	uint32_t* ms_session_id;
} ms_session_request_t;

typedef struct ms_exchange_report_t {
	uint32_t ms_retval;
	sgx_dh_dcap_msg2_t* ms_dh_msg2;
	sgx_dh_dcap_msg3_t* ms_dh_msg3;
	uint32_t ms_session_id;
} ms_exchange_report_t;

typedef struct ms_end_session_t {
	uint32_t ms_retval;
	uint32_t ms_session_id;
} ms_end_session_t;

typedef struct ms_ecdsa_quote_verification_ocall_t {
	uint32_t ms_retval;
	uint8_t* ms_quote_buffer;
	uint32_t ms_quote_size;
} ms_ecdsa_quote_verification_ocall_t;

typedef struct ms_ecdsa_quote_generation_ocall_t {
	uint32_t ms_retval;
	uint32_t* ms_quote_size;
	sgx_report_t* ms_app_report;
	uint8_t* ms_quote;
} ms_ecdsa_quote_generation_ocall_t;

typedef struct ms_ecdsa_get_qe_target_info_ocall_t {
	uint32_t ms_retval;
	sgx_target_info_t* ms_qe_target_info;
} ms_ecdsa_get_qe_target_info_ocall_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_rdtsc_t {
	uint64_t ms_retval;
} ms_ocall_rdtsc_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

typedef struct ms_ocall_http_get_t {
	int ms_retval;
	void* ms_ptr;
} ms_ocall_http_get_t;

typedef struct ms_ocall_open_t {
	int ms_retval;
	const char* ms_pathname;
	int ms_flags;
	bool ms_has_mode;
	unsigned int ms_mode;
} ms_ocall_open_t;

typedef struct ms_ocall_openat_t {
	int ms_retval;
	int ms_dirfd;
	const char* ms_pathname;
	int ms_flags;
	bool ms_has_mode;
	unsigned int ms_mode;
} ms_ocall_openat_t;

typedef struct ms_ocall_close_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_close_t;

typedef struct ms_ocall_read_t {
	ssize_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_read_size;
} ms_ocall_read_t;

typedef struct ms_ocall_lseek_t {
	off_t ms_retval;
	int ms_fd;
	off_t ms_offset;
	int ms_whence;
} ms_ocall_lseek_t;

typedef struct ms_ocall_ftruncate_t {
	int ms_retval;
	int ms_fd;
	off_t ms_length;
} ms_ocall_ftruncate_t;

typedef struct ms_ocall_fsync_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_fsync_t;

typedef struct ms_ocall_fdatasync_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_fdatasync_t;

typedef struct ms_ocall_isatty_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_isatty_t;

typedef struct ms_ocall_fdopendir_t {
	int ms_fd;
	void** ms_p_dirp;
} ms_ocall_fdopendir_t;

typedef struct ms_ocall_readdir_t {
	void* ms_retval;
	void* ms_dirp;
} ms_ocall_readdir_t;

typedef struct ms_ocall_rewinddir_t {
	void* ms_dirp;
} ms_ocall_rewinddir_t;

typedef struct ms_ocall_seekdir_t {
	void* ms_dirp;
	long int ms_loc;
} ms_ocall_seekdir_t;

typedef struct ms_ocall_telldir_t {
	long int ms_retval;
	void* ms_dirp;
} ms_ocall_telldir_t;

typedef struct ms_ocall_closedir_t {
	int ms_retval;
	void* ms_dirp;
} ms_ocall_closedir_t;

typedef struct ms_ocall_stat_t {
	int ms_retval;
	const char* ms_pathname;
	void* ms_buf;
	unsigned int ms_buf_len;
} ms_ocall_stat_t;

typedef struct ms_ocall_fstat_t {
	int ms_retval;
	int ms_fd;
	void* ms_buf;
	unsigned int ms_buf_len;
} ms_ocall_fstat_t;

typedef struct ms_ocall_fstatat_t {
	int ms_retval;
	int ms_dirfd;
	const char* ms_pathname;
	void* ms_buf;
	unsigned int ms_buf_len;
	int ms_flags;
} ms_ocall_fstatat_t;

typedef struct ms_ocall_mkdirat_t {
	int ms_retval;
	int ms_dirfd;
	const char* ms_pathname;
	unsigned int ms_mode;
} ms_ocall_mkdirat_t;

typedef struct ms_ocall_link_t {
	int ms_retval;
	const char* ms_oldpath;
	const char* ms_newpath;
} ms_ocall_link_t;

typedef struct ms_ocall_linkat_t {
	int ms_retval;
	int ms_olddirfd;
	const char* ms_oldpath;
	int ms_newdirfd;
	const char* ms_newpath;
	int ms_flags;
} ms_ocall_linkat_t;

typedef struct ms_ocall_unlinkat_t {
	int ms_retval;
	int ms_dirfd;
	const char* ms_pathname;
	int ms_flags;
} ms_ocall_unlinkat_t;

typedef struct ms_ocall_readlinkat_t {
	ssize_t ms_retval;
	int ms_dirfd;
	const char* ms_pathname;
	char* ms_buf;
	size_t ms_bufsiz;
} ms_ocall_readlinkat_t;

typedef struct ms_ocall_renameat_t {
	int ms_retval;
	int ms_olddirfd;
	const char* ms_oldpath;
	int ms_newdirfd;
	const char* ms_newpath;
} ms_ocall_renameat_t;

typedef struct ms_ocall_symlinkat_t {
	int ms_retval;
	const char* ms_target;
	int ms_newdirfd;
	const char* ms_linkpath;
} ms_ocall_symlinkat_t;

typedef struct ms_ocall_ioctl_t {
	int ms_retval;
	int ms_fd;
	unsigned long int ms_request;
	void* ms_arg;
	unsigned int ms_arg_len;
} ms_ocall_ioctl_t;

typedef struct ms_ocall_fcntl_t {
	int ms_retval;
	int ms_fd;
	int ms_cmd;
} ms_ocall_fcntl_t;

typedef struct ms_ocall_fcntl_long_t {
	int ms_retval;
	int ms_fd;
	int ms_cmd;
	long int ms_arg;
} ms_ocall_fcntl_long_t;

typedef struct ms_ocall_realpath_t {
	int ms_retval;
	const char* ms_path;
	char* ms_buf;
	unsigned int ms_buf_len;
} ms_ocall_realpath_t;

typedef struct ms_ocall_posix_fallocate_t {
	int ms_retval;
	int ms_fd;
	off_t ms_offset;
	off_t ms_len;
} ms_ocall_posix_fallocate_t;

typedef struct ms_ocall_poll_t {
	int ms_retval;
	void* ms_fds;
	unsigned int ms_nfds;
	int ms_timeout;
	unsigned int ms_fds_len;
} ms_ocall_poll_t;

typedef struct ms_ocall_getopt_t {
	int ms_retval;
	int ms_argc;
	char* ms_argv_buf;
	unsigned int ms_argv_buf_len;
	const char* ms_optstring;
} ms_ocall_getopt_t;

typedef struct ms_ocall_getrandom_t {
	ssize_t ms_retval;
	void* ms_buf;
	size_t ms_buflen;
	unsigned int ms_flags;
} ms_ocall_getrandom_t;

typedef struct ms_ocall_getentropy_t {
	int ms_retval;
	void* ms_buffer;
	size_t ms_length;
} ms_ocall_getentropy_t;

typedef struct ms_ocall_readv_t {
	ssize_t ms_retval;
	int ms_fd;
	char* ms_iov_buf;
	unsigned int ms_buf_size;
	int ms_iovcnt;
	bool ms_has_offset;
	off_t ms_offset;
} ms_ocall_readv_t;

typedef struct ms_ocall_writev_t {
	ssize_t ms_retval;
	int ms_fd;
	char* ms_iov_buf;
	unsigned int ms_buf_size;
	int ms_iovcnt;
	bool ms_has_offset;
	off_t ms_offset;
} ms_ocall_writev_t;

typedef struct ms_ocall_clock_gettime_t {
	int ms_retval;
	unsigned int ms_clock_id;
	void* ms_tp_buf;
	unsigned int ms_tp_buf_size;
} ms_ocall_clock_gettime_t;

typedef struct ms_ocall_clock_getres_t {
	int ms_retval;
	int ms_clock_id;
	void* ms_res_buf;
	unsigned int ms_res_buf_size;
} ms_ocall_clock_getres_t;

typedef struct ms_ocall_utimensat_t {
	int ms_retval;
	int ms_dirfd;
	const char* ms_pathname;
	const void* ms_times_buf;
	unsigned int ms_times_buf_size;
	int ms_flags;
} ms_ocall_utimensat_t;

typedef struct ms_ocall_futimens_t {
	int ms_retval;
	int ms_fd;
	const void* ms_times_buf;
	unsigned int ms_times_buf_size;
} ms_ocall_futimens_t;

typedef struct ms_ocall_clock_nanosleep_t {
	int ms_retval;
	unsigned int ms_clock_id;
	int ms_flags;
	const void* ms_req_buf;
	unsigned int ms_req_buf_size;
	void* ms_rem_buf;
	unsigned int ms_rem_buf_size;
} ms_ocall_clock_nanosleep_t;

typedef struct ms_ocall_raise_t {
	int ms_retval;
	int ms_sig;
} ms_ocall_raise_t;

typedef struct ms_ocall_sched_yield_t {
	int ms_retval;
} ms_ocall_sched_yield_t;

typedef struct ms_ocall_pthread_rwlock_init_t {
	int ms_retval;
	void** ms_rwlock;
	void* ms_attr;
} ms_ocall_pthread_rwlock_init_t;

typedef struct ms_ocall_pthread_rwlock_destroy_t {
	int ms_retval;
	void* ms_rwlock;
} ms_ocall_pthread_rwlock_destroy_t;

typedef struct ms_ocall_pthread_rwlock_rdlock_t {
	int ms_retval;
	void* ms_rwlock;
} ms_ocall_pthread_rwlock_rdlock_t;

typedef struct ms_ocall_pthread_rwlock_wrlock_t {
	int ms_retval;
	void* ms_rwlock;
} ms_ocall_pthread_rwlock_wrlock_t;

typedef struct ms_ocall_pthread_rwlock_unlock_t {
	int ms_retval;
	void* ms_rwlock;
} ms_ocall_pthread_rwlock_unlock_t;

typedef struct ms_ocall_get_errno_t {
	int ms_retval;
} ms_ocall_get_errno_t;

typedef struct ms_ocall_socket_t {
	int ms_retval;
	int ms_domain;
	int ms_type;
	int ms_protocol;
} ms_ocall_socket_t;

typedef struct ms_ocall_getsockopt_t {
	int ms_retval;
	int ms_sockfd;
	int ms_level;
	int ms_optname;
	void* ms_val_buf;
	unsigned int ms_val_buf_size;
	void* ms_len_buf;
} ms_ocall_getsockopt_t;

typedef struct ms_ocall_sendmsg_t {
	ssize_t ms_retval;
	int ms_sockfd;
	void* ms_msg_buf;
	unsigned int ms_msg_buf_size;
	int ms_flags;
} ms_ocall_sendmsg_t;

typedef struct ms_ocall_recvmsg_t {
	ssize_t ms_retval;
	int ms_sockfd;
	void* ms_msg_buf;
	unsigned int ms_msg_buf_size;
	int ms_flags;
} ms_ocall_recvmsg_t;

typedef struct ms_ocall_shutdown_t {
	int ms_retval;
	int ms_sockfd;
	int ms_how;
} ms_ocall_shutdown_t;

static sgx_status_t SGX_CDECL sgx_ecall_handle_command(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_handle_command_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_handle_command_t* ms = SGX_CAST(ms_ecall_handle_command_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_cmd_buf = ms->ms_cmd_buf;
	unsigned int _tmp_cmd_buf_size = ms->ms_cmd_buf_size;
	size_t _len_cmd_buf = _tmp_cmd_buf_size;
	uint8_t* _in_cmd_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_cmd_buf, _len_cmd_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_cmd_buf != NULL && _len_cmd_buf != 0) {
		if ( _len_cmd_buf % sizeof(*_tmp_cmd_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_cmd_buf = (uint8_t*)malloc(_len_cmd_buf);
		if (_in_cmd_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cmd_buf, _len_cmd_buf, _tmp_cmd_buf, _len_cmd_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_handle_command(ms->ms_cmd, _in_cmd_buf, _tmp_cmd_buf_size);
	if (_in_cmd_buf) {
		if (memcpy_s(_tmp_cmd_buf, _len_cmd_buf, _in_cmd_buf, _len_cmd_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_cmd_buf) free(_in_cmd_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_iwasm_main(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_iwasm_main_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_iwasm_main_t* ms = SGX_CAST(ms_ecall_iwasm_main_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_wasm_file_buf = ms->ms_wasm_file_buf;



	ecall_iwasm_main(_tmp_wasm_file_buf, ms->ms_wasm_file_size);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_nskernel_snapshot(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_nskernel_snapshot();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_nskernel_rollback(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_nskernel_rollback();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_nskernel_set_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_nskernel_set_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_nskernel_set_key_t* ms = SGX_CAST(ms_ecall_nskernel_set_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_key = ms->ms_key;



	ecall_nskernel_set_key(_tmp_key);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_nskernel_generate_ecdsa_key(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_nskernel_generate_ecdsa_key();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_nskernel_generate_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_nskernel_generate_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_nskernel_generate_report_t* ms = SGX_CAST(ms_ecall_nskernel_generate_report_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_data = ms->ms_data;
	uint8_t* _tmp_report = ms->ms_report;
	uint8_t* _tmp_signature = ms->ms_signature;



	ms->ms_retval = ecall_nskernel_generate_report(_tmp_data, _tmp_report, _tmp_signature);


	return status;
}

static sgx_status_t SGX_CDECL sgx_session_request(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_session_request_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_session_request_t* ms = SGX_CAST(ms_session_request_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_dh_dcap_msg1_t* _tmp_dh_msg1 = ms->ms_dh_msg1;
	size_t _len_dh_msg1 = sizeof(sgx_dh_dcap_msg1_t);
	sgx_dh_dcap_msg1_t* _in_dh_msg1 = NULL;
	uint32_t* _tmp_session_id = ms->ms_session_id;
	size_t _len_session_id = sizeof(uint32_t);
	uint32_t* _in_session_id = NULL;

	CHECK_UNIQUE_POINTER(_tmp_dh_msg1, _len_dh_msg1);
	CHECK_UNIQUE_POINTER(_tmp_session_id, _len_session_id);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_dh_msg1 != NULL && _len_dh_msg1 != 0) {
		if ((_in_dh_msg1 = (sgx_dh_dcap_msg1_t*)malloc(_len_dh_msg1)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_msg1, 0, _len_dh_msg1);
	}
	if (_tmp_session_id != NULL && _len_session_id != 0) {
		if ( _len_session_id % sizeof(*_tmp_session_id) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_session_id = (uint32_t*)malloc(_len_session_id)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_session_id, 0, _len_session_id);
	}

	ms->ms_retval = session_request(_in_dh_msg1, _in_session_id);
	if (_in_dh_msg1) {
		if (memcpy_s(_tmp_dh_msg1, _len_dh_msg1, _in_dh_msg1, _len_dh_msg1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_session_id) {
		if (memcpy_s(_tmp_session_id, _len_session_id, _in_session_id, _len_session_id)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_dh_msg1) free(_in_dh_msg1);
	if (_in_session_id) free(_in_session_id);
	return status;
}

static sgx_status_t SGX_CDECL sgx_exchange_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_exchange_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_exchange_report_t* ms = SGX_CAST(ms_exchange_report_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_dh_dcap_msg2_t* _tmp_dh_msg2 = ms->ms_dh_msg2;
	size_t _len_dh_msg2 = sizeof(sgx_dh_dcap_msg2_t);
	sgx_dh_dcap_msg2_t* _in_dh_msg2 = NULL;
	sgx_dh_dcap_msg3_t* _tmp_dh_msg3 = ms->ms_dh_msg3;
	size_t _len_dh_msg3 = sizeof(sgx_dh_dcap_msg3_t);
	sgx_dh_dcap_msg3_t* _in_dh_msg3 = NULL;

	CHECK_UNIQUE_POINTER(_tmp_dh_msg2, _len_dh_msg2);
	CHECK_UNIQUE_POINTER(_tmp_dh_msg3, _len_dh_msg3);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_dh_msg2 != NULL && _len_dh_msg2 != 0) {
		_in_dh_msg2 = (sgx_dh_dcap_msg2_t*)malloc(_len_dh_msg2);
		if (_in_dh_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_dh_msg2, _len_dh_msg2, _tmp_dh_msg2, _len_dh_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_dh_msg3 != NULL && _len_dh_msg3 != 0) {
		if ((_in_dh_msg3 = (sgx_dh_dcap_msg3_t*)malloc(_len_dh_msg3)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_msg3, 0, _len_dh_msg3);
	}

	ms->ms_retval = exchange_report(_in_dh_msg2, _in_dh_msg3, ms->ms_session_id);
	if (_in_dh_msg3) {
		if (memcpy_s(_tmp_dh_msg3, _len_dh_msg3, _in_dh_msg3, _len_dh_msg3)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_dh_msg2) free(_in_dh_msg2);
	if (_in_dh_msg3) free(_in_dh_msg3);
	return status;
}

static sgx_status_t SGX_CDECL sgx_end_session(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_end_session_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_end_session_t* ms = SGX_CAST(ms_end_session_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = end_session(ms->ms_session_id);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[10];
} g_ecall_table = {
	10,
	{
		{(void*)(uintptr_t)sgx_ecall_handle_command, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_iwasm_main, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_nskernel_snapshot, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_nskernel_rollback, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_nskernel_set_key, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_nskernel_generate_ecdsa_key, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_nskernel_generate_report, 0, 0},
		{(void*)(uintptr_t)sgx_session_request, 0, 0},
		{(void*)(uintptr_t)sgx_exchange_report, 0, 0},
		{(void*)(uintptr_t)sgx_end_session, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[68][10];
} g_dyn_entry_table = {
	68,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ecdsa_quote_verification_ocall(uint32_t* retval, uint8_t* quote_buffer, uint32_t quote_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_quote_buffer = SGX_QUOTE3_BUFFER_SIZE;

	ms_ecdsa_quote_verification_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ecdsa_quote_verification_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(quote_buffer, _len_quote_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (quote_buffer != NULL) ? _len_quote_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ecdsa_quote_verification_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ecdsa_quote_verification_ocall_t));
	ocalloc_size -= sizeof(ms_ecdsa_quote_verification_ocall_t);

	if (quote_buffer != NULL) {
		ms->ms_quote_buffer = (uint8_t*)__tmp;
		if (_len_quote_buffer % sizeof(*quote_buffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, quote_buffer, _len_quote_buffer)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_quote_buffer);
		ocalloc_size -= _len_quote_buffer;
	} else {
		ms->ms_quote_buffer = NULL;
	}
	
	ms->ms_quote_size = quote_size;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ecdsa_quote_generation_ocall(uint32_t* retval, uint32_t* quote_size, sgx_report_t* app_report, uint8_t* quote)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_quote_size = sizeof(uint32_t);
	size_t _len_app_report = sizeof(sgx_report_t);
	size_t _len_quote = SGX_QUOTE3_BUFFER_SIZE;

	ms_ecdsa_quote_generation_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ecdsa_quote_generation_ocall_t);
	void *__tmp = NULL;

	void *__tmp_quote_size = NULL;
	void *__tmp_quote = NULL;

	CHECK_ENCLAVE_POINTER(quote_size, _len_quote_size);
	CHECK_ENCLAVE_POINTER(app_report, _len_app_report);
	CHECK_ENCLAVE_POINTER(quote, _len_quote);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (quote_size != NULL) ? _len_quote_size : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (app_report != NULL) ? _len_app_report : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (quote != NULL) ? _len_quote : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ecdsa_quote_generation_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ecdsa_quote_generation_ocall_t));
	ocalloc_size -= sizeof(ms_ecdsa_quote_generation_ocall_t);

	if (quote_size != NULL) {
		ms->ms_quote_size = (uint32_t*)__tmp;
		__tmp_quote_size = __tmp;
		if (_len_quote_size % sizeof(*quote_size) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_quote_size, 0, _len_quote_size);
		__tmp = (void *)((size_t)__tmp + _len_quote_size);
		ocalloc_size -= _len_quote_size;
	} else {
		ms->ms_quote_size = NULL;
	}
	
	if (app_report != NULL) {
		ms->ms_app_report = (sgx_report_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, app_report, _len_app_report)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_app_report);
		ocalloc_size -= _len_app_report;
	} else {
		ms->ms_app_report = NULL;
	}
	
	if (quote != NULL) {
		ms->ms_quote = (uint8_t*)__tmp;
		__tmp_quote = __tmp;
		if (_len_quote % sizeof(*quote) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_quote, 0, _len_quote);
		__tmp = (void *)((size_t)__tmp + _len_quote);
		ocalloc_size -= _len_quote;
	} else {
		ms->ms_quote = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (quote_size) {
			if (memcpy_s((void*)quote_size, _len_quote_size, __tmp_quote_size, _len_quote_size)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (quote) {
			if (memcpy_s((void*)quote, _len_quote, __tmp_quote, _len_quote)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ecdsa_get_qe_target_info_ocall(uint32_t* retval, sgx_target_info_t* qe_target_info)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_qe_target_info = sizeof(sgx_target_info_t);

	ms_ecdsa_get_qe_target_info_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ecdsa_get_qe_target_info_ocall_t);
	void *__tmp = NULL;

	void *__tmp_qe_target_info = NULL;

	CHECK_ENCLAVE_POINTER(qe_target_info, _len_qe_target_info);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (qe_target_info != NULL) ? _len_qe_target_info : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ecdsa_get_qe_target_info_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ecdsa_get_qe_target_info_ocall_t));
	ocalloc_size -= sizeof(ms_ecdsa_get_qe_target_info_ocall_t);

	if (qe_target_info != NULL) {
		ms->ms_qe_target_info = (sgx_target_info_t*)__tmp;
		__tmp_qe_target_info = __tmp;
		memset(__tmp_qe_target_info, 0, _len_qe_target_info);
		__tmp = (void *)((size_t)__tmp + _len_qe_target_info);
		ocalloc_size -= _len_qe_target_info;
	} else {
		ms->ms_qe_target_info = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (qe_target_info) {
			if (memcpy_s((void*)qe_target_info, _len_qe_target_info, __tmp_qe_target_info, _len_qe_target_info)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_rdtsc(uint64_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_rdtsc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_rdtsc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_rdtsc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_rdtsc_t));
	ocalloc_size -= sizeof(ms_ocall_rdtsc_t);

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wait_timeout_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wait_timeout_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wait_timeout_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wait_timeout_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wait_timeout_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_timeout = timeout;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_create_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_create_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_create_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_create_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_create_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wakeup_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wakeup_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wakeup_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wakeup_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wakeup_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_http_get(int* retval, void* ptr)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_http_get_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_http_get_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_http_get_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_http_get_t));
	ocalloc_size -= sizeof(ms_ocall_http_get_t);

	ms->ms_ptr = ptr;
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_open(int* retval, const char* pathname, int flags, bool has_mode, unsigned int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_ocall_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_open_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_open_t));
	ocalloc_size -= sizeof(ms_ocall_open_t);

	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	ms->ms_flags = flags;
	ms->ms_has_mode = has_mode;
	ms->ms_mode = mode;
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_openat(int* retval, int dirfd, const char* pathname, int flags, bool has_mode, unsigned int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_ocall_openat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_openat_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_openat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_openat_t));
	ocalloc_size -= sizeof(ms_ocall_openat_t);

	ms->ms_dirfd = dirfd;
	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	ms->ms_flags = flags;
	ms->ms_has_mode = has_mode;
	ms->ms_mode = mode;
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_close(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_close_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_close_t));
	ocalloc_size -= sizeof(ms_ocall_close_t);

	ms->ms_fd = fd;
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read(ssize_t* retval, int fd, void* buf, size_t read_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = read_size;

	ms_ocall_read_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_t));
	ocalloc_size -= sizeof(ms_ocall_read_t);

	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_read_size = read_size;
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_lseek(off_t* retval, int fd, off_t offset, int whence)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_lseek_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_lseek_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_lseek_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_lseek_t));
	ocalloc_size -= sizeof(ms_ocall_lseek_t);

	ms->ms_fd = fd;
	ms->ms_offset = offset;
	ms->ms_whence = whence;
	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_ftruncate(int* retval, int fd, off_t length)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_ftruncate_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_ftruncate_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_ftruncate_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_ftruncate_t));
	ocalloc_size -= sizeof(ms_ocall_ftruncate_t);

	ms->ms_fd = fd;
	ms->ms_length = length;
	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fsync(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fsync_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fsync_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fsync_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fsync_t));
	ocalloc_size -= sizeof(ms_ocall_fsync_t);

	ms->ms_fd = fd;
	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fdatasync(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fdatasync_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fdatasync_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fdatasync_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fdatasync_t));
	ocalloc_size -= sizeof(ms_ocall_fdatasync_t);

	ms->ms_fd = fd;
	status = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_isatty(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_isatty_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_isatty_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_isatty_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_isatty_t));
	ocalloc_size -= sizeof(ms_ocall_isatty_t);

	ms->ms_fd = fd;
	status = sgx_ocall(22, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fdopendir(int fd, void** p_dirp)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_dirp = sizeof(void*);

	ms_ocall_fdopendir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fdopendir_t);
	void *__tmp = NULL;

	void *__tmp_p_dirp = NULL;

	CHECK_ENCLAVE_POINTER(p_dirp, _len_p_dirp);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_dirp != NULL) ? _len_p_dirp : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fdopendir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fdopendir_t));
	ocalloc_size -= sizeof(ms_ocall_fdopendir_t);

	ms->ms_fd = fd;
	if (p_dirp != NULL) {
		ms->ms_p_dirp = (void**)__tmp;
		__tmp_p_dirp = __tmp;
		if (_len_p_dirp % sizeof(*p_dirp) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_p_dirp, 0, _len_p_dirp);
		__tmp = (void *)((size_t)__tmp + _len_p_dirp);
		ocalloc_size -= _len_p_dirp;
	} else {
		ms->ms_p_dirp = NULL;
	}
	
	status = sgx_ocall(23, ms);

	if (status == SGX_SUCCESS) {
		if (p_dirp) {
			if (memcpy_s((void*)p_dirp, _len_p_dirp, __tmp_p_dirp, _len_p_dirp)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_readdir(void** retval, void* dirp)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_readdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readdir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readdir_t));
	ocalloc_size -= sizeof(ms_ocall_readdir_t);

	ms->ms_dirp = dirp;
	status = sgx_ocall(24, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_rewinddir(void* dirp)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_rewinddir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_rewinddir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_rewinddir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_rewinddir_t));
	ocalloc_size -= sizeof(ms_ocall_rewinddir_t);

	ms->ms_dirp = dirp;
	status = sgx_ocall(25, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_seekdir(void* dirp, long int loc)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_seekdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_seekdir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_seekdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_seekdir_t));
	ocalloc_size -= sizeof(ms_ocall_seekdir_t);

	ms->ms_dirp = dirp;
	ms->ms_loc = loc;
	status = sgx_ocall(26, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_telldir(long int* retval, void* dirp)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_telldir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_telldir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_telldir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_telldir_t));
	ocalloc_size -= sizeof(ms_ocall_telldir_t);

	ms->ms_dirp = dirp;
	status = sgx_ocall(27, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_closedir(int* retval, void* dirp)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_closedir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_closedir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_closedir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_closedir_t));
	ocalloc_size -= sizeof(ms_ocall_closedir_t);

	ms->ms_dirp = dirp;
	status = sgx_ocall(28, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_stat(int* retval, const char* pathname, void* buf, unsigned int buf_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;
	size_t _len_buf = buf_len;

	ms_ocall_stat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_stat_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_stat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_stat_t));
	ocalloc_size -= sizeof(ms_ocall_stat_t);

	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_buf_len = buf_len;
	status = sgx_ocall(29, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fstat(int* retval, int fd, void* buf, unsigned int buf_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = buf_len;

	ms_ocall_fstat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fstat_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fstat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fstat_t));
	ocalloc_size -= sizeof(ms_ocall_fstat_t);

	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_buf_len = buf_len;
	status = sgx_ocall(30, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fstatat(int* retval, int dirfd, const char* pathname, void* buf, unsigned int buf_len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;
	size_t _len_buf = buf_len;

	ms_ocall_fstatat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fstatat_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fstatat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fstatat_t));
	ocalloc_size -= sizeof(ms_ocall_fstatat_t);

	ms->ms_dirfd = dirfd;
	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_buf_len = buf_len;
	ms->ms_flags = flags;
	status = sgx_ocall(31, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mkdirat(int* retval, int dirfd, const char* pathname, unsigned int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_ocall_mkdirat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mkdirat_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mkdirat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mkdirat_t));
	ocalloc_size -= sizeof(ms_ocall_mkdirat_t);

	ms->ms_dirfd = dirfd;
	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	ms->ms_mode = mode;
	status = sgx_ocall(32, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_link(int* retval, const char* oldpath, const char* newpath)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_oldpath = oldpath ? strlen(oldpath) + 1 : 0;
	size_t _len_newpath = newpath ? strlen(newpath) + 1 : 0;

	ms_ocall_link_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_link_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(oldpath, _len_oldpath);
	CHECK_ENCLAVE_POINTER(newpath, _len_newpath);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (oldpath != NULL) ? _len_oldpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (newpath != NULL) ? _len_newpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_link_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_link_t));
	ocalloc_size -= sizeof(ms_ocall_link_t);

	if (oldpath != NULL) {
		ms->ms_oldpath = (const char*)__tmp;
		if (_len_oldpath % sizeof(*oldpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, oldpath, _len_oldpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_oldpath);
		ocalloc_size -= _len_oldpath;
	} else {
		ms->ms_oldpath = NULL;
	}
	
	if (newpath != NULL) {
		ms->ms_newpath = (const char*)__tmp;
		if (_len_newpath % sizeof(*newpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, newpath, _len_newpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_newpath);
		ocalloc_size -= _len_newpath;
	} else {
		ms->ms_newpath = NULL;
	}
	
	status = sgx_ocall(33, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_linkat(int* retval, int olddirfd, const char* oldpath, int newdirfd, const char* newpath, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_oldpath = oldpath ? strlen(oldpath) + 1 : 0;
	size_t _len_newpath = newpath ? strlen(newpath) + 1 : 0;

	ms_ocall_linkat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_linkat_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(oldpath, _len_oldpath);
	CHECK_ENCLAVE_POINTER(newpath, _len_newpath);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (oldpath != NULL) ? _len_oldpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (newpath != NULL) ? _len_newpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_linkat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_linkat_t));
	ocalloc_size -= sizeof(ms_ocall_linkat_t);

	ms->ms_olddirfd = olddirfd;
	if (oldpath != NULL) {
		ms->ms_oldpath = (const char*)__tmp;
		if (_len_oldpath % sizeof(*oldpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, oldpath, _len_oldpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_oldpath);
		ocalloc_size -= _len_oldpath;
	} else {
		ms->ms_oldpath = NULL;
	}
	
	ms->ms_newdirfd = newdirfd;
	if (newpath != NULL) {
		ms->ms_newpath = (const char*)__tmp;
		if (_len_newpath % sizeof(*newpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, newpath, _len_newpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_newpath);
		ocalloc_size -= _len_newpath;
	} else {
		ms->ms_newpath = NULL;
	}
	
	ms->ms_flags = flags;
	status = sgx_ocall(34, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_unlinkat(int* retval, int dirfd, const char* pathname, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_ocall_unlinkat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_unlinkat_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_unlinkat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_unlinkat_t));
	ocalloc_size -= sizeof(ms_ocall_unlinkat_t);

	ms->ms_dirfd = dirfd;
	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	ms->ms_flags = flags;
	status = sgx_ocall(35, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_readlinkat(ssize_t* retval, int dirfd, const char* pathname, char* buf, size_t bufsiz)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;
	size_t _len_buf = bufsiz;

	ms_ocall_readlinkat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readlinkat_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readlinkat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readlinkat_t));
	ocalloc_size -= sizeof(ms_ocall_readlinkat_t);

	ms->ms_dirfd = dirfd;
	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	if (buf != NULL) {
		ms->ms_buf = (char*)__tmp;
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_bufsiz = bufsiz;
	status = sgx_ocall(36, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_renameat(int* retval, int olddirfd, const char* oldpath, int newdirfd, const char* newpath)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_oldpath = oldpath ? strlen(oldpath) + 1 : 0;
	size_t _len_newpath = newpath ? strlen(newpath) + 1 : 0;

	ms_ocall_renameat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_renameat_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(oldpath, _len_oldpath);
	CHECK_ENCLAVE_POINTER(newpath, _len_newpath);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (oldpath != NULL) ? _len_oldpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (newpath != NULL) ? _len_newpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_renameat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_renameat_t));
	ocalloc_size -= sizeof(ms_ocall_renameat_t);

	ms->ms_olddirfd = olddirfd;
	if (oldpath != NULL) {
		ms->ms_oldpath = (const char*)__tmp;
		if (_len_oldpath % sizeof(*oldpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, oldpath, _len_oldpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_oldpath);
		ocalloc_size -= _len_oldpath;
	} else {
		ms->ms_oldpath = NULL;
	}
	
	ms->ms_newdirfd = newdirfd;
	if (newpath != NULL) {
		ms->ms_newpath = (const char*)__tmp;
		if (_len_newpath % sizeof(*newpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, newpath, _len_newpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_newpath);
		ocalloc_size -= _len_newpath;
	} else {
		ms->ms_newpath = NULL;
	}
	
	status = sgx_ocall(37, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_symlinkat(int* retval, const char* target, int newdirfd, const char* linkpath)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_target = target ? strlen(target) + 1 : 0;
	size_t _len_linkpath = linkpath ? strlen(linkpath) + 1 : 0;

	ms_ocall_symlinkat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_symlinkat_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(target, _len_target);
	CHECK_ENCLAVE_POINTER(linkpath, _len_linkpath);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (target != NULL) ? _len_target : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (linkpath != NULL) ? _len_linkpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_symlinkat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_symlinkat_t));
	ocalloc_size -= sizeof(ms_ocall_symlinkat_t);

	if (target != NULL) {
		ms->ms_target = (const char*)__tmp;
		if (_len_target % sizeof(*target) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, target, _len_target)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_target);
		ocalloc_size -= _len_target;
	} else {
		ms->ms_target = NULL;
	}
	
	ms->ms_newdirfd = newdirfd;
	if (linkpath != NULL) {
		ms->ms_linkpath = (const char*)__tmp;
		if (_len_linkpath % sizeof(*linkpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, linkpath, _len_linkpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_linkpath);
		ocalloc_size -= _len_linkpath;
	} else {
		ms->ms_linkpath = NULL;
	}
	
	status = sgx_ocall(38, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_ioctl(int* retval, int fd, unsigned long int request, void* arg, unsigned int arg_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_arg = arg_len;

	ms_ocall_ioctl_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_ioctl_t);
	void *__tmp = NULL;

	void *__tmp_arg = NULL;

	CHECK_ENCLAVE_POINTER(arg, _len_arg);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (arg != NULL) ? _len_arg : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_ioctl_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_ioctl_t));
	ocalloc_size -= sizeof(ms_ocall_ioctl_t);

	ms->ms_fd = fd;
	ms->ms_request = request;
	if (arg != NULL) {
		ms->ms_arg = (void*)__tmp;
		__tmp_arg = __tmp;
		memset(__tmp_arg, 0, _len_arg);
		__tmp = (void *)((size_t)__tmp + _len_arg);
		ocalloc_size -= _len_arg;
	} else {
		ms->ms_arg = NULL;
	}
	
	ms->ms_arg_len = arg_len;
	status = sgx_ocall(39, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (arg) {
			if (memcpy_s((void*)arg, _len_arg, __tmp_arg, _len_arg)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fcntl(int* retval, int fd, int cmd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fcntl_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fcntl_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fcntl_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fcntl_t));
	ocalloc_size -= sizeof(ms_ocall_fcntl_t);

	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	status = sgx_ocall(40, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fcntl_long(int* retval, int fd, int cmd, long int arg)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fcntl_long_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fcntl_long_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fcntl_long_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fcntl_long_t));
	ocalloc_size -= sizeof(ms_ocall_fcntl_long_t);

	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	ms->ms_arg = arg;
	status = sgx_ocall(41, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_realpath(int* retval, const char* path, char* buf, unsigned int buf_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = buf_len;

	ms_ocall_realpath_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_realpath_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_realpath_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_realpath_t));
	ocalloc_size -= sizeof(ms_ocall_realpath_t);

	if (path != NULL) {
		ms->ms_path = (const char*)__tmp;
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}
	
	if (buf != NULL) {
		ms->ms_buf = (char*)__tmp;
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_buf_len = buf_len;
	status = sgx_ocall(42, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_posix_fallocate(int* retval, int fd, off_t offset, off_t len)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_posix_fallocate_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_posix_fallocate_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_posix_fallocate_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_posix_fallocate_t));
	ocalloc_size -= sizeof(ms_ocall_posix_fallocate_t);

	ms->ms_fd = fd;
	ms->ms_offset = offset;
	ms->ms_len = len;
	status = sgx_ocall(43, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_poll(int* retval, void* fds, unsigned int nfds, int timeout, unsigned int fds_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fds = fds_len;

	ms_ocall_poll_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_poll_t);
	void *__tmp = NULL;

	void *__tmp_fds = NULL;

	CHECK_ENCLAVE_POINTER(fds, _len_fds);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fds != NULL) ? _len_fds : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_poll_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_poll_t));
	ocalloc_size -= sizeof(ms_ocall_poll_t);

	if (fds != NULL) {
		ms->ms_fds = (void*)__tmp;
		__tmp_fds = __tmp;
		memset(__tmp_fds, 0, _len_fds);
		__tmp = (void *)((size_t)__tmp + _len_fds);
		ocalloc_size -= _len_fds;
	} else {
		ms->ms_fds = NULL;
	}
	
	ms->ms_nfds = nfds;
	ms->ms_timeout = timeout;
	ms->ms_fds_len = fds_len;
	status = sgx_ocall(44, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (fds) {
			if (memcpy_s((void*)fds, _len_fds, __tmp_fds, _len_fds)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getopt(int* retval, int argc, char* argv_buf, unsigned int argv_buf_len, const char* optstring)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_argv_buf = argv_buf_len;
	size_t _len_optstring = optstring ? strlen(optstring) + 1 : 0;

	ms_ocall_getopt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getopt_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(argv_buf, _len_argv_buf);
	CHECK_ENCLAVE_POINTER(optstring, _len_optstring);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (argv_buf != NULL) ? _len_argv_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (optstring != NULL) ? _len_optstring : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getopt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getopt_t));
	ocalloc_size -= sizeof(ms_ocall_getopt_t);

	ms->ms_argc = argc;
	if (argv_buf != NULL) {
		ms->ms_argv_buf = (char*)__tmp;
		if (_len_argv_buf % sizeof(*argv_buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, argv_buf, _len_argv_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_argv_buf);
		ocalloc_size -= _len_argv_buf;
	} else {
		ms->ms_argv_buf = NULL;
	}
	
	ms->ms_argv_buf_len = argv_buf_len;
	if (optstring != NULL) {
		ms->ms_optstring = (const char*)__tmp;
		if (_len_optstring % sizeof(*optstring) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, optstring, _len_optstring)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_optstring);
		ocalloc_size -= _len_optstring;
	} else {
		ms->ms_optstring = NULL;
	}
	
	status = sgx_ocall(45, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getrandom(ssize_t* retval, void* buf, size_t buflen, unsigned int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = buflen;

	ms_ocall_getrandom_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getrandom_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getrandom_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getrandom_t));
	ocalloc_size -= sizeof(ms_ocall_getrandom_t);

	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_buflen = buflen;
	ms->ms_flags = flags;
	status = sgx_ocall(46, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getentropy(int* retval, void* buffer, size_t length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = length;

	ms_ocall_getentropy_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getentropy_t);
	void *__tmp = NULL;

	void *__tmp_buffer = NULL;

	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getentropy_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getentropy_t));
	ocalloc_size -= sizeof(ms_ocall_getentropy_t);

	if (buffer != NULL) {
		ms->ms_buffer = (void*)__tmp;
		__tmp_buffer = __tmp;
		memset(__tmp_buffer, 0, _len_buffer);
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}
	
	ms->ms_length = length;
	status = sgx_ocall(47, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buffer) {
			if (memcpy_s((void*)buffer, _len_buffer, __tmp_buffer, _len_buffer)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_readv(ssize_t* retval, int fd, char* iov_buf, unsigned int buf_size, int iovcnt, bool has_offset, off_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_iov_buf = buf_size;

	ms_ocall_readv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readv_t);
	void *__tmp = NULL;

	void *__tmp_iov_buf = NULL;

	CHECK_ENCLAVE_POINTER(iov_buf, _len_iov_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (iov_buf != NULL) ? _len_iov_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readv_t));
	ocalloc_size -= sizeof(ms_ocall_readv_t);

	ms->ms_fd = fd;
	if (iov_buf != NULL) {
		ms->ms_iov_buf = (char*)__tmp;
		__tmp_iov_buf = __tmp;
		if (_len_iov_buf % sizeof(*iov_buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, iov_buf, _len_iov_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_iov_buf);
		ocalloc_size -= _len_iov_buf;
	} else {
		ms->ms_iov_buf = NULL;
	}
	
	ms->ms_buf_size = buf_size;
	ms->ms_iovcnt = iovcnt;
	ms->ms_has_offset = has_offset;
	ms->ms_offset = offset;
	status = sgx_ocall(48, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (iov_buf) {
			if (memcpy_s((void*)iov_buf, _len_iov_buf, __tmp_iov_buf, _len_iov_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_writev(ssize_t* retval, int fd, char* iov_buf, unsigned int buf_size, int iovcnt, bool has_offset, off_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_iov_buf = buf_size;

	ms_ocall_writev_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_writev_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(iov_buf, _len_iov_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (iov_buf != NULL) ? _len_iov_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_writev_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_writev_t));
	ocalloc_size -= sizeof(ms_ocall_writev_t);

	ms->ms_fd = fd;
	if (iov_buf != NULL) {
		ms->ms_iov_buf = (char*)__tmp;
		if (_len_iov_buf % sizeof(*iov_buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, iov_buf, _len_iov_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_iov_buf);
		ocalloc_size -= _len_iov_buf;
	} else {
		ms->ms_iov_buf = NULL;
	}
	
	ms->ms_buf_size = buf_size;
	ms->ms_iovcnt = iovcnt;
	ms->ms_has_offset = has_offset;
	ms->ms_offset = offset;
	status = sgx_ocall(49, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_clock_gettime(int* retval, unsigned int clock_id, void* tp_buf, unsigned int tp_buf_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tp_buf = tp_buf_size;

	ms_ocall_clock_gettime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_clock_gettime_t);
	void *__tmp = NULL;

	void *__tmp_tp_buf = NULL;

	CHECK_ENCLAVE_POINTER(tp_buf, _len_tp_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tp_buf != NULL) ? _len_tp_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_clock_gettime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_clock_gettime_t));
	ocalloc_size -= sizeof(ms_ocall_clock_gettime_t);

	ms->ms_clock_id = clock_id;
	if (tp_buf != NULL) {
		ms->ms_tp_buf = (void*)__tmp;
		__tmp_tp_buf = __tmp;
		memset(__tmp_tp_buf, 0, _len_tp_buf);
		__tmp = (void *)((size_t)__tmp + _len_tp_buf);
		ocalloc_size -= _len_tp_buf;
	} else {
		ms->ms_tp_buf = NULL;
	}
	
	ms->ms_tp_buf_size = tp_buf_size;
	status = sgx_ocall(50, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (tp_buf) {
			if (memcpy_s((void*)tp_buf, _len_tp_buf, __tmp_tp_buf, _len_tp_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_clock_getres(int* retval, int clock_id, void* res_buf, unsigned int res_buf_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_res_buf = res_buf_size;

	ms_ocall_clock_getres_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_clock_getres_t);
	void *__tmp = NULL;

	void *__tmp_res_buf = NULL;

	CHECK_ENCLAVE_POINTER(res_buf, _len_res_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (res_buf != NULL) ? _len_res_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_clock_getres_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_clock_getres_t));
	ocalloc_size -= sizeof(ms_ocall_clock_getres_t);

	ms->ms_clock_id = clock_id;
	if (res_buf != NULL) {
		ms->ms_res_buf = (void*)__tmp;
		__tmp_res_buf = __tmp;
		memset(__tmp_res_buf, 0, _len_res_buf);
		__tmp = (void *)((size_t)__tmp + _len_res_buf);
		ocalloc_size -= _len_res_buf;
	} else {
		ms->ms_res_buf = NULL;
	}
	
	ms->ms_res_buf_size = res_buf_size;
	status = sgx_ocall(51, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (res_buf) {
			if (memcpy_s((void*)res_buf, _len_res_buf, __tmp_res_buf, _len_res_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_utimensat(int* retval, int dirfd, const char* pathname, const void* times_buf, unsigned int times_buf_size, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;
	size_t _len_times_buf = times_buf_size;

	ms_ocall_utimensat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_utimensat_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);
	CHECK_ENCLAVE_POINTER(times_buf, _len_times_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (times_buf != NULL) ? _len_times_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_utimensat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_utimensat_t));
	ocalloc_size -= sizeof(ms_ocall_utimensat_t);

	ms->ms_dirfd = dirfd;
	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	if (times_buf != NULL) {
		ms->ms_times_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, times_buf, _len_times_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_times_buf);
		ocalloc_size -= _len_times_buf;
	} else {
		ms->ms_times_buf = NULL;
	}
	
	ms->ms_times_buf_size = times_buf_size;
	ms->ms_flags = flags;
	status = sgx_ocall(52, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_futimens(int* retval, int fd, const void* times_buf, unsigned int times_buf_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_times_buf = times_buf_size;

	ms_ocall_futimens_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_futimens_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(times_buf, _len_times_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (times_buf != NULL) ? _len_times_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_futimens_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_futimens_t));
	ocalloc_size -= sizeof(ms_ocall_futimens_t);

	ms->ms_fd = fd;
	if (times_buf != NULL) {
		ms->ms_times_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, times_buf, _len_times_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_times_buf);
		ocalloc_size -= _len_times_buf;
	} else {
		ms->ms_times_buf = NULL;
	}
	
	ms->ms_times_buf_size = times_buf_size;
	status = sgx_ocall(53, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_clock_nanosleep(int* retval, unsigned int clock_id, int flags, const void* req_buf, unsigned int req_buf_size, void* rem_buf, unsigned int rem_buf_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_req_buf = req_buf_size;
	size_t _len_rem_buf = rem_buf_size;

	ms_ocall_clock_nanosleep_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_clock_nanosleep_t);
	void *__tmp = NULL;

	void *__tmp_rem_buf = NULL;

	CHECK_ENCLAVE_POINTER(req_buf, _len_req_buf);
	CHECK_ENCLAVE_POINTER(rem_buf, _len_rem_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (req_buf != NULL) ? _len_req_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (rem_buf != NULL) ? _len_rem_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_clock_nanosleep_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_clock_nanosleep_t));
	ocalloc_size -= sizeof(ms_ocall_clock_nanosleep_t);

	ms->ms_clock_id = clock_id;
	ms->ms_flags = flags;
	if (req_buf != NULL) {
		ms->ms_req_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, req_buf, _len_req_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_req_buf);
		ocalloc_size -= _len_req_buf;
	} else {
		ms->ms_req_buf = NULL;
	}
	
	ms->ms_req_buf_size = req_buf_size;
	if (rem_buf != NULL) {
		ms->ms_rem_buf = (void*)__tmp;
		__tmp_rem_buf = __tmp;
		memset(__tmp_rem_buf, 0, _len_rem_buf);
		__tmp = (void *)((size_t)__tmp + _len_rem_buf);
		ocalloc_size -= _len_rem_buf;
	} else {
		ms->ms_rem_buf = NULL;
	}
	
	ms->ms_rem_buf_size = rem_buf_size;
	status = sgx_ocall(54, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (rem_buf) {
			if (memcpy_s((void*)rem_buf, _len_rem_buf, __tmp_rem_buf, _len_rem_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_raise(int* retval, int sig)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_raise_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_raise_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_raise_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_raise_t));
	ocalloc_size -= sizeof(ms_ocall_raise_t);

	ms->ms_sig = sig;
	status = sgx_ocall(55, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sched_yield(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sched_yield_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sched_yield_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sched_yield_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sched_yield_t));
	ocalloc_size -= sizeof(ms_ocall_sched_yield_t);

	status = sgx_ocall(56, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_rwlock_init(int* retval, void** rwlock, void* attr)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_rwlock = sizeof(void*);

	ms_ocall_pthread_rwlock_init_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_rwlock_init_t);
	void *__tmp = NULL;

	void *__tmp_rwlock = NULL;

	CHECK_ENCLAVE_POINTER(rwlock, _len_rwlock);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (rwlock != NULL) ? _len_rwlock : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_rwlock_init_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_rwlock_init_t));
	ocalloc_size -= sizeof(ms_ocall_pthread_rwlock_init_t);

	if (rwlock != NULL) {
		ms->ms_rwlock = (void**)__tmp;
		__tmp_rwlock = __tmp;
		if (_len_rwlock % sizeof(*rwlock) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_rwlock, 0, _len_rwlock);
		__tmp = (void *)((size_t)__tmp + _len_rwlock);
		ocalloc_size -= _len_rwlock;
	} else {
		ms->ms_rwlock = NULL;
	}
	
	ms->ms_attr = attr;
	status = sgx_ocall(57, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (rwlock) {
			if (memcpy_s((void*)rwlock, _len_rwlock, __tmp_rwlock, _len_rwlock)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_rwlock_destroy(int* retval, void* rwlock)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_rwlock_destroy_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_rwlock_destroy_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_rwlock_destroy_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_rwlock_destroy_t));
	ocalloc_size -= sizeof(ms_ocall_pthread_rwlock_destroy_t);

	ms->ms_rwlock = rwlock;
	status = sgx_ocall(58, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_rwlock_rdlock(int* retval, void* rwlock)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_rwlock_rdlock_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_rwlock_rdlock_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_rwlock_rdlock_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_rwlock_rdlock_t));
	ocalloc_size -= sizeof(ms_ocall_pthread_rwlock_rdlock_t);

	ms->ms_rwlock = rwlock;
	status = sgx_ocall(59, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_rwlock_wrlock(int* retval, void* rwlock)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_rwlock_wrlock_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_rwlock_wrlock_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_rwlock_wrlock_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_rwlock_wrlock_t));
	ocalloc_size -= sizeof(ms_ocall_pthread_rwlock_wrlock_t);

	ms->ms_rwlock = rwlock;
	status = sgx_ocall(60, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_rwlock_unlock(int* retval, void* rwlock)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_rwlock_unlock_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_rwlock_unlock_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_rwlock_unlock_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_rwlock_unlock_t));
	ocalloc_size -= sizeof(ms_ocall_pthread_rwlock_unlock_t);

	ms->ms_rwlock = rwlock;
	status = sgx_ocall(61, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_errno(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_get_errno_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_errno_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_errno_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_errno_t));
	ocalloc_size -= sizeof(ms_ocall_get_errno_t);

	status = sgx_ocall(62, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_socket(int* retval, int domain, int type, int protocol)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_socket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_socket_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_socket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_socket_t));
	ocalloc_size -= sizeof(ms_ocall_socket_t);

	ms->ms_domain = domain;
	ms->ms_type = type;
	ms->ms_protocol = protocol;
	status = sgx_ocall(63, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getsockopt(int* retval, int sockfd, int level, int optname, void* val_buf, unsigned int val_buf_size, void* len_buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val_buf = val_buf_size;
	size_t _len_len_buf = 4;

	ms_ocall_getsockopt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getsockopt_t);
	void *__tmp = NULL;

	void *__tmp_val_buf = NULL;
	void *__tmp_len_buf = NULL;

	CHECK_ENCLAVE_POINTER(val_buf, _len_val_buf);
	CHECK_ENCLAVE_POINTER(len_buf, _len_len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (val_buf != NULL) ? _len_val_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (len_buf != NULL) ? _len_len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getsockopt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getsockopt_t));
	ocalloc_size -= sizeof(ms_ocall_getsockopt_t);

	ms->ms_sockfd = sockfd;
	ms->ms_level = level;
	ms->ms_optname = optname;
	if (val_buf != NULL) {
		ms->ms_val_buf = (void*)__tmp;
		__tmp_val_buf = __tmp;
		memset(__tmp_val_buf, 0, _len_val_buf);
		__tmp = (void *)((size_t)__tmp + _len_val_buf);
		ocalloc_size -= _len_val_buf;
	} else {
		ms->ms_val_buf = NULL;
	}
	
	ms->ms_val_buf_size = val_buf_size;
	if (len_buf != NULL) {
		ms->ms_len_buf = (void*)__tmp;
		__tmp_len_buf = __tmp;
		if (memcpy_s(__tmp, ocalloc_size, len_buf, _len_len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_len_buf);
		ocalloc_size -= _len_len_buf;
	} else {
		ms->ms_len_buf = NULL;
	}
	
	status = sgx_ocall(64, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (val_buf) {
			if (memcpy_s((void*)val_buf, _len_val_buf, __tmp_val_buf, _len_val_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (len_buf) {
			if (memcpy_s((void*)len_buf, _len_len_buf, __tmp_len_buf, _len_len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sendmsg(ssize_t* retval, int sockfd, void* msg_buf, unsigned int msg_buf_size, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_msg_buf = msg_buf_size;

	ms_ocall_sendmsg_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sendmsg_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(msg_buf, _len_msg_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (msg_buf != NULL) ? _len_msg_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sendmsg_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sendmsg_t));
	ocalloc_size -= sizeof(ms_ocall_sendmsg_t);

	ms->ms_sockfd = sockfd;
	if (msg_buf != NULL) {
		ms->ms_msg_buf = (void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, msg_buf, _len_msg_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_msg_buf);
		ocalloc_size -= _len_msg_buf;
	} else {
		ms->ms_msg_buf = NULL;
	}
	
	ms->ms_msg_buf_size = msg_buf_size;
	ms->ms_flags = flags;
	status = sgx_ocall(65, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_recvmsg(ssize_t* retval, int sockfd, void* msg_buf, unsigned int msg_buf_size, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_msg_buf = msg_buf_size;

	ms_ocall_recvmsg_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_recvmsg_t);
	void *__tmp = NULL;

	void *__tmp_msg_buf = NULL;

	CHECK_ENCLAVE_POINTER(msg_buf, _len_msg_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (msg_buf != NULL) ? _len_msg_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_recvmsg_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_recvmsg_t));
	ocalloc_size -= sizeof(ms_ocall_recvmsg_t);

	ms->ms_sockfd = sockfd;
	if (msg_buf != NULL) {
		ms->ms_msg_buf = (void*)__tmp;
		__tmp_msg_buf = __tmp;
		if (memcpy_s(__tmp, ocalloc_size, msg_buf, _len_msg_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_msg_buf);
		ocalloc_size -= _len_msg_buf;
	} else {
		ms->ms_msg_buf = NULL;
	}
	
	ms->ms_msg_buf_size = msg_buf_size;
	ms->ms_flags = flags;
	status = sgx_ocall(66, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (msg_buf) {
			if (memcpy_s((void*)msg_buf, _len_msg_buf, __tmp_msg_buf, _len_msg_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_shutdown(int* retval, int sockfd, int how)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_shutdown_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_shutdown_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_shutdown_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_shutdown_t));
	ocalloc_size -= sizeof(ms_ocall_shutdown_t);

	ms->ms_sockfd = sockfd;
	ms->ms_how = how;
	status = sgx_ocall(67, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

