#include <stddef.h>
#include <stdint.h>

#define TRACE_OCALL_FAIL() os_printf("ocall %s failed!\n", __FUNCTION__)

#include "Enclave_t.h"
#include "bh_platform.h"

int ow_http_get(void *ptr) {
    int ret;

    if (ocall_http_get(&ret, ptr) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    return ret;
}
