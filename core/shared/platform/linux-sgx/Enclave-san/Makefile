# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

######## SGX SDK Settings ########
SGX_SDK ?= /home/nskernel/linux-sgx-san/linux/installer/bin/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
SPEC_TEST ?= 0
NSKERNEL_SIGN_ALGO ?= ECDSA

WASM_LIB_DIR := build-san-aot
WASM_ULIB_DIR := build-aot

TCC = /home/nskernel/llvm-project/build/bin/clang
TCXX = /home/nskernel/llvm-project/build/bin/clang++

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	#SGX_LIBRARY_PATH := /home/nskernel/linux-sgx/linux/installer/bin/sgxsdk/lib64
	SGX_ENCLAVE_SIGNER := /home/nskernel/linux-sgx/linux/installer/bin/sgxsdk/bin/x64/sgx_sign
	SGX_EDGER8R := /home/nskernel/linux-sgx/linux/installer/bin/sgxsdk/bin/x64/sgx_edger8r
endif

ifeq ($(NSKERNEL_SIGN_ALGO), RSA)
	SGX_COMMON_CFLAGS := -DNSKERNEL_USE_RSA
else ifeq ($(NSKERNEL_SIGN_ALGO), ECDSA)
	SGX_COMMON_CFLAGS := -DNSKERNEL_USE_ECDSA
else
	SGX_COMMON_CFLAGS := -DNSKERNEL_USE_AES
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

WAMR_ROOT := $(CURDIR)/../../../../../

Enclave_C_Files := SecuredFunctions.c http_get.c Enclave.c ecp.c EnclaveMessageExchange.c
Enclave_Cpp_Files:= 

Enclave_Include_Paths := -IEnclave -I$(WAMR_ROOT)/core/iwasm/include \
                         -I$(WAMR_ROOT)/core/shared/utils \
                         -I$(WAMR_ROOT)/core/shared/platform/linux-sgx \
                         -I$(SGX_SDK)/include \
                         -I$(SGX_SDK)/include/tlibc \
                         -I$(SGX_SDK)/include/libcxx \
			 -I$(SGX_SDK)/include/stlport

Enclave_C_Flags := $(SGX_COMMON_CFLAGS)  -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths) -fno-zero-initialized-in-bss
ifeq ($(SPEC_TEST), 1)
	Enclave_C_Flags += -DWASM_ENABLE_SPEC_TEST=1
else
	Enclave_C_Flags += -DWASM_ENABLE_SPEC_TEST=0
endif
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
    libvmlib.a \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_pthread -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,-Tldscript_sanitized

Enclave_C_Objects := $(Enclave_C_Files:.c=.o) avx_memset.o

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(Signed_Enclave_Name)
endif

######## Enclave Objects ########

Enclave_t.h: $(SGX_EDGER8R) Enclave.edl
	$(SGX_EDGER8R) --trusted Enclave.edl \
		--search-path ../Enclave \
		--search-path $(SGX_SDK)/include \
		--search-path $(WAMR_ROOT)/core/shared/platform/linux-sgx
	@echo "GEN  =>  $@"

Enclave_t.c: Enclave_t.h

Enclave_t.o: Enclave_t.c
	@$(TCC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

avx_memset.o: avx_memset.S
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "AS   <=  $<"

tdcap_dh.o: tdcap_dh.cpp
	@$(TCXX) $(Enclave_C_Flags) -std=c++11 -nostdinc++ -c $< -o $@
	@echo "CXX  <=  $<"


%.o: %.c
	@$(TCC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Enclave_Name): Enclave_t.o $(Enclave_C_Objects) tdcap_dh.o libvmlib.a
	$(TCXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f $(Enclave_Name) $(Signed_Enclave_Name) $(Enclave_C_Objects) Enclave_t.* 
