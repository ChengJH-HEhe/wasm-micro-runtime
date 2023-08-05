/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <map>
#include <sys/stat.h>
#include <sched.h>

#include "Enclave_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"

#include "cpdef.h"
#include "fifo_def.h"
#include "datatypes.h"

#include "CPTask.h"
#include "CPServer.h"

extern "C" sgx_enclave_id_t e2_enclave_id = 0;

/* Function Description:
 *  This function responds to initiator enclave's connection request by generating and sending back ECDH message 1
 * Parameter Description:
 *  [input] clientfd: this is client's connection id. After generating ECDH message 1, server would send back response through this connection id.
 * */
int generate_and_send_session_msg1_resp(int clientfd)
{
    int retcode = 0;
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    SESSION_MSG1_RESP msg1resp;
    FIFO_MSG * fifo_resp = NULL;
    size_t respmsgsize;

    memset(&msg1resp, 0, sizeof(SESSION_MSG1_RESP));

    // call wasm vm enclave to generate ECDH message 1
    ret = session_request(e2_enclave_id, &status, &msg1resp.dh_msg1, &msg1resp.sessionid);
    if (ret != SGX_SUCCESS)
    {
        printf("failed to do ECALL session_request. enclave_id = %d\n", e2_enclave_id);
        return -1;
    }
    
    respmsgsize = sizeof(FIFO_MSG) + sizeof(SESSION_MSG1_RESP);
    fifo_resp = (FIFO_MSG *)malloc(respmsgsize);
    if (!fifo_resp)
    {
        printf("memory allocation failure.\n");
        return -1;
    }
    memset(fifo_resp, 0, respmsgsize);

    fifo_resp->header.type = FIFO_DH_RESP_MSG1;
    fifo_resp->header.size = sizeof(SESSION_MSG1_RESP);
    
    memcpy(fifo_resp->msgbuf, &msg1resp, sizeof(SESSION_MSG1_RESP));
    
    //send message 1 to client
    if (send(clientfd, reinterpret_cast<char *>(fifo_resp), static_cast<int>(respmsgsize), 0) == -1)
    {
        printf("fail to send msg1 response.\n");
        retcode = -1;
    }
    free(fifo_resp);
    return retcode;
}

/* Function Description:
 *  This function process ECDH message 2 received from client and send message 3 to client
 * Parameter Description:
 *  [input] clientfd: this is client's connection id
 *  [input] msg2: this contains ECDH message 2 received from client
 * */
int process_exchange_report(int clientfd, SESSION_MSG2 * msg2)
{
    uint32_t status = 0;
        sgx_status_t ret = SGX_SUCCESS;
    FIFO_MSG *response;
    SESSION_MSG3 * msg3;
    size_t msgsize;
    
    if (!msg2)
        return -1;
    
    msgsize = sizeof(FIFO_MSG_HEADER) + sizeof(SESSION_MSG3);
    response = (FIFO_MSG *)malloc(msgsize);
    if (!response)
    {
        printf("memory allocation failure\n");
        return -1;
    }
    memset(response, 0, msgsize);
    
    response->header.type = FIFO_DH_MSG3;
    response->header.size = sizeof(SESSION_MSG3);
    
    msg3 = (SESSION_MSG3 *)response->msgbuf;
    msg3->sessionid = msg2->sessionid; 

    // call wasm vm enclave to process ECDH message 2 and generate message 3
    ret = exchange_report(e2_enclave_id, &status, &msg2->dh_msg2, &msg3->dh_msg3, msg2->sessionid);
    if (ret != SGX_SUCCESS)
    {
        printf("EnclaveResponse_exchange_report failure.\n");
        free(response);
        return -1;
    }

    // send ECDH message 3 to client
    if (send(clientfd, reinterpret_cast<char *>(response), static_cast<int>(msgsize), 0) == -1)
    {
        printf("server_send() failure.\n");
        free(response);
        return -1;
    }

    free(response);

    return 0;
}

/* Function Description:
 *  This function process received message communication from client
 * Parameter Description:
 *  [input] clientfd: this is client's connection id
 *  [input] req_msg: this is pointer to received message from client
 * */
/*int process_msg_transfer(int clientfd, FIFO_MSGBODY_REQ *req_msg)
{
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    secure_message_t *resp_message = NULL;
    FIFO_MSG * fifo_resp = NULL;
    size_t resp_message_size;
    if (!req_msg)
    {
        printf("invalid parameter.\n");
        return -1;
    }

    resp_message_size = sizeof(secure_message_t) + req_msg->max_payload_size;
    //Allocate memory for the response message
    resp_message = (secure_message_t*)malloc(resp_message_size);
    if (!resp_message)
    {
        printf("memory allocation failure.\n");
        return -1;
    }
    memset(resp_message, 0, resp_message_size);
    ret = generate_response(e2_enclave_id, &status, (secure_message_t *)req_msg->buf, req_msg->size, req_msg->max_payload_size, resp_message, resp_message_size, req_msg->session_id);
    if (ret != SGX_SUCCESS)
    {
        printf("WASMVMEnclave_generate_response error.\n");
        free(resp_message);
        return -1;
    }

    fifo_resp = (FIFO_MSG *)malloc(sizeof(FIFO_MSG) + resp_message_size);
    if (!fifo_resp)
    {
        printf("memory allocation failure.\n");
        free(resp_message);
        return -1;
    }
    memset(fifo_resp, 0, sizeof(FIFO_MSG) + resp_message_size);

    fifo_resp->header.type = FIFO_DH_MSG_RESP;
    fifo_resp->header.size = resp_message_size;
    memcpy(fifo_resp->msgbuf, resp_message, resp_message_size);

    free(resp_message);

    if (send(clientfd, reinterpret_cast<char *>(fifo_resp), sizeof(FIFO_MSG) + static_cast<int>(resp_message_size), 0) == -1)
    {
        printf("server_send() failure.\n");
        free(fifo_resp);
        return -1;
    }
    free(fifo_resp);

    return 0;
}*/

/* Function Description: This is process session close request from client
 * Parameter Description:
 *  [input] clientfd: this is client connection id
 *  [input] close_req: this is pointer to client's session close request
 * */
int process_close_req(int clientfd, SESSION_CLOSE_REQ * close_req)
{
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    FIFO_MSG close_ack;
    
    if (!close_req)
        return -1; 

    // call wasm vm enclave to close this session
    ret = end_session(e2_enclave_id, &status, close_req->session_id);
    if (ret != SGX_SUCCESS)
        return -1;

    // send back response
    close_ack.header.type = FIFO_DH_CLOSE_RESP;
    close_ack.header.size = 0;

    if (send(clientfd, reinterpret_cast<char *>(&close_ack), sizeof(FIFO_MSG), 0) == -1)
    {
        printf("server_send() failure.\n");
        return -1;
    }

    return 0;
}

#include "sgx_dcap_ql_wrapper.h"
#include "sgx_quote_3.h"

/**
 * @param qe_target_info - [out]ECDSA qe target info
 */
uint32_t ecdsa_get_qe_target_info_ocall(sgx_target_info_t* qe_target_info){
	uint32_t ret = 0;
	quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    sgx_target_info_t qe3_target_info;

    // There 2 modes on Linux: one is in-proc mode, the QE3 and PCE are loaded within the user's process.
    // the other is out-of-proc mode, the QE3 and PCE are managed by a daemon. If you want to use in-proc
    // mode which is the default mode, you only need to install libsgx-dcap-ql. If you want to use the
    // out-of-proc mode, you need to install libsgx-quote-ex as well. This sample is built to demo both 2
    // modes, so you need to install libsgx-quote-ex to enable the out-of-proc mode.
        // Following functions are valid in Linux in-proc mode only.
        printf("sgx_qe_set_enclave_load_policy is valid in in-proc mode only and it is optional: the default enclave load policy is persistent: \n");
        printf("set the enclave load policy as persistent:");
        qe3_ret = sgx_qe_set_enclave_load_policy(SGX_QL_PERSISTENT);
        if(SGX_QL_SUCCESS != qe3_ret) {
            printf("Error in set enclave load policy: 0x%04x\n", qe3_ret);
            ret = -1;
            goto CLEANUP;
        }
        printf("succeed!\n");

        // Try to load PCE and QE3 from Ubuntu-like OS system path
        if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so") ||
                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so")) {

            // Try to load PCE and QE3 from RHEL-like OS system path
            if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib64/libsgx_pce.signed.so") ||
                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib64/libsgx_qe3.signed.so")) {
                printf("Error in set PCE/QE3 directory.\n");
                ret = -1;
                goto CLEANUP;
            }
        }

        qe3_ret = sgx_ql_set_path(SGX_QL_QPL_PATH, "/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1");
        if (SGX_QL_SUCCESS != qe3_ret) {
            qe3_ret = sgx_ql_set_path(SGX_QL_QPL_PATH, "/usr/lib64/libdcap_quoteprov.so.1");
            if(SGX_QL_SUCCESS != qe3_ret) {
                // Ignore the error, because user may want to get cert type=3 quote
                printf("Warning: Cannot set QPL directory, you may get ECDSA quote with `Encrypted PPID` cert type.\n");
            }
        }

    printf("\nStep1: Call sgx_qe_get_target_info:");
    qe3_ret = sgx_qe_get_target_info(&qe3_target_info);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf("Error in sgx_qe_get_target_info. 0x%04x\n", qe3_ret);
                ret = -1;
        goto CLEANUP;
    }
    printf("succeed!");

	memcpy(qe_target_info, &qe3_target_info, sizeof(qe3_target_info));

	CLEANUP:
    return ret;
}

/**
 * @param app_report [in] sgx_report_t* app_report
 * @param quote_buffer - [out]ECDSA quote buffer
 * @param quote_size - [out]ECDSA quote buffer size
 */
uint32_t ecdsa_quote_generation_ocall(uint32_t* quote_size, sgx_report_t* app_report, uint8_t* quote_buffer){
	uint32_t ret = 0;
	quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    uint8_t *p_quote_buffer = NULL;

    sgx_quote3_t *p_quote;
    sgx_ql_auth_data_t *p_auth_data;
    sgx_ql_ecdsa_sig_data_t *p_sig_data;
    sgx_ql_certification_data_t *p_cert_data;
    printf("\nStep2: Call create_app_report:");
    

    printf("succeed!");
    printf("\nStep3: Call sgx_qe_get_quote_size:");
    qe3_ret = sgx_qe_get_quote_size(quote_size);
    if (SGX_QL_SUCCESS != qe3_ret)
    {
        printf("Error in sgx_qe_get_quote_size. 0x%04x\n", qe3_ret);
        goto CLEANUP;
    }
	printf("succeed!");
    p_quote_buffer = (uint8_t *)malloc(*quote_size);
    if (NULL == p_quote_buffer)
    {
        printf("Couldn't allocate quote_buffer\n");
        goto CLEANUP;
    }
    memset(p_quote_buffer, 0, *quote_size);

    // Get the Quote
    printf("\nStep4: Call sgx_qe_get_quote:");
    qe3_ret = sgx_qe_get_quote(app_report,
                               *quote_size,
                               p_quote_buffer);
    if (SGX_QL_SUCCESS != qe3_ret)
    {
        printf("Error in sgx_qe_get_quote. 0x%04x\n", qe3_ret);
        goto CLEANUP;
    }
    printf("succeed!");

	memcpy(quote_buffer, p_quote_buffer, *quote_size);
    p_quote = (sgx_quote3_t *)p_quote_buffer;
    p_sig_data = (sgx_ql_ecdsa_sig_data_t *)p_quote->signature_data;
    p_auth_data = (sgx_ql_auth_data_t *)p_sig_data->auth_certification_data;
    p_cert_data = (sgx_ql_certification_data_t *)((uint8_t *)p_auth_data + sizeof(*p_auth_data) + p_auth_data->size);

    printf("cert_key_type = 0x%x\n", p_cert_data->cert_key_type);
	
	CLEANUP:
    if (NULL != p_quote_buffer) {
        free(p_quote_buffer);
    }
    return ret;
}

#include "sgx_dcap_quoteverify.h"

/**
 * @param quote_buffer - [in]ECDSA quote buffer
 * @param quote_size - [in]ECDSA quote buffer size
 */
uint32_t ecdsa_quote_verification_ocall(uint8_t* quote_buffer, uint32_t quote_size)
{
    uint32_t ret = 0;
    time_t current_time = 0;
    uint32_t supplemental_data_size = 0;
    uint8_t *p_supplemental_data = NULL;
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    uint32_t collateral_expiration_status = 1;

    printf("size of quote will be verified : %ld\n", quote_size);
    // Untrusted quote verification
    // call DCAP quote verify library to get supplemental data size
    //
    dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (dcap_ret == SGX_QL_SUCCESS && supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t))
    {
        printf("\tInfo: sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
        p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
    }
    else
    {
        if (dcap_ret != SGX_QL_SUCCESS)
            printf("\tError: sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", dcap_ret);

        if (supplemental_data_size != sizeof(sgx_ql_qv_supplemental_t))
            printf("\tWarning: sgx_qv_get_quote_supplemental_data_size returned size is not same with header definition in SGX SDK, please make sure you are using same version of SGX SDK and DCAP QVL.\n");

        supplemental_data_size = 0;
    }

    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    current_time = time(NULL);

    // call DCAP quote verify library for quote verification
    // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
    // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
    // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    dcap_ret = sgx_qv_verify_quote(
        (uint8_t*)quote_buffer, quote_size,
        NULL,
        current_time,
        &collateral_expiration_status,
        &quote_verification_result,
        NULL,
        supplemental_data_size,
        p_supplemental_data);
    if (dcap_ret == SGX_QL_SUCCESS)
    {
        printf("\tInfo: App: sgx_qv_verify_quote successfully returned.\n");
    }
    else
    {
        printf("\tError: App: sgx_qv_verify_quote failed: 0x%04x\n", dcap_ret);
    }

    // check verification result
    //
    switch (quote_verification_result)
    {
    case SGX_QL_QV_RESULT_OK:
        // check verification collateral expiration status
        // this value should be considered in your own attestation/verification policy
        //
        if (collateral_expiration_status == 0)
        {
            printf("\tInfo: App: Verification completed successfully.\n");
            ret = 0;
        }
        else
        {
            printf("\tWarning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.\n");
            ret = 1;
        }
        break;
    case SGX_QL_QV_RESULT_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_OUT_OF_DATE:
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
    case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        printf("\tWarning: App: Verification completed with Non-terminal result: %x\n", quote_verification_result);
        ret = 1;
        break;
    case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
    case SGX_QL_QV_RESULT_REVOKED:
    case SGX_QL_QV_RESULT_UNSPECIFIED:
    default:
        printf("\tError: App: Verification completed with Terminal result: %x\n", quote_verification_result);
        ret = -1;
        break;
    }

    // check supplemental data if necessary
    //
    if (p_supplemental_data != NULL && supplemental_data_size > 0)
    {
        sgx_ql_qv_supplemental_t *p = (sgx_ql_qv_supplemental_t *)p_supplemental_data;

        // you can check supplemental data based on your own attestation/verification policy
        // here we only print supplemental data version for demo usage
        //
        printf("\tInfo: Supplemental data version: %d\n", p->version);
    }

    return ret;
}

#include <ctime>

uint64_t
time_diff(struct timespec *ts1, struct timespec *ts2) {
    uint64_t t1;
    uint64_t t2;

    t1 = ts1->tv_sec * 1000000000 + ts1->tv_nsec;
    t2 = ts2->tv_sec * 1000000000 + ts2->tv_nsec;
    return t2 - t1;
}

void CPTask::run()
{
    FIFO_MSG * message = NULL;
    sgx_launch_token_t token = {0};
    sgx_status_t status;
    int update = 0;
    struct timespec ts1;
    struct timespec ts2;


    while (!isStopped())
    {
        /* receive task frome queue */
        message  = m_queue.blockingPop();
        if (isStopped())
        {
            free(message);
            break;
        }

        switch (message->header.type)
        {
            case FIFO_DH_REQ_MSG1:
            {
                // process ECDH session connection request
                printf("process ECDH session connection request\n");
                int clientfd = message->header.sockfd;
                if (generate_and_send_session_msg1_resp(clientfd) != 0)
                {
                    printf("failed to generate and send session msg1 resp.\n");
                    break;
                }
                printf("process ECDH session connection request success\n");
            }
            break;

            case FIFO_DH_MSG2:
            {
                // process ECDH message 2
                printf("process ECDH message 2\n");
                int clientfd = message->header.sockfd;
                SESSION_MSG2 * msg2 = NULL;
                msg2 = (SESSION_MSG2 *)message->msgbuf;

                if (process_exchange_report(clientfd, msg2) != 0)
                {
                    printf("failed to process exchange_report request.\n");
                    break;
                }
                printf("process ECDH message 2 success\n");
            }
            break;

            /*case FIFO_DH_MSG_REQ: // Not available in OpenWhisk
            {
                // process message transfer request
                printf("process message transfer request\n");
                int clientfd = message->header.sockfd;
                FIFO_MSGBODY_REQ *msg = NULL;
                msg = (FIFO_MSGBODY_REQ *)message->msgbuf;
                if (process_msg_transfer(clientfd, msg) != 0)   
                {
                    printf("failed to process message transfer request.\n");
                    break;
                }
                printf("process message transfer request success\n");       
            }
            break;*/

            case FIFO_DH_CLOSE_REQ:
            {
                printf("process message close request\n"); 
                // process message close request
                int clientfd = message->header.sockfd;
                SESSION_CLOSE_REQ * closereq = NULL;

                closereq = (SESSION_CLOSE_REQ *)message->msgbuf;

                process_close_req(clientfd, closereq);
                printf("process message close request success\n"); 
            }
            break;
        default:
            {
                printf("Unknown message.\n");
            }
            break;
        }

        free(message);
        message = NULL;
    }

    sgx_destroy_enclave(e2_enclave_id);
}

void CPTask::shutdown()
{
    stop();
    m_queue.close();
    join();
}

void CPTask::puttask(FIFO_MSG* requestData)
{
    if (isStopped()) {
        return;
    }
    
    m_queue.push(requestData);
}

