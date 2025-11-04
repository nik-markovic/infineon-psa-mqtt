/*****************************************************************************
* File Name        : main.c
*
* Description      : This source file contains the main routine for non-secure
*                    application in the CM33 CPU
*
* Related Document : See README.md
*
*******************************************************************************
# \copyright
# (c) 2024-2025, Infineon Technologies AG, or an affiliate of Infineon Technologies AG.
# SPDX-License-Identifier: Apache-2.0
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
*******************************************************************************/

/*******************************************************************************
* Header Files
*******************************************************************************/

#include <stdio.h>
#include "cyabs_rtos_impl.h"
#include "cybsp.h"
#include "cy_pdl.h"
#include "tfm_ns_interface.h"
#include "os_wrapper/common.h"
#include "psa/internal_trusted_storage.h"
#include "ifx_platform_api.h"
#include "psa/crypto.h"


/*******************************************************************************
* Macros
*******************************************************************************/

/* Internal Trusted Storage UID */
#define ITS_UID                     (1U)

/* Buffer size for Internal Trusted Storage */
#define ITS_BUFF_SIZE               (20U)

/* The timeout value in microseconds used to wait for CM55 core to be booted */
#define CM55_BOOT_WAIT_TIME_USEC    (10U)

/* App boot address for CM55 project */
#define CM55_APP_BOOT_ADDR          (CYMEM_CM33_0_m55_nvm_START + \
                                        CYBSP_MCUBOOT_HEADER_SIZE)


/*******************************************************************************
* Global Variables
*******************************************************************************/


/*******************************************************************************
* Function Prototypes
*******************************************************************************/
void print_num(const char* format, int num) {
    unsigned char out_buf[256];
    int buf_size = sprintf((char*)out_buf, format, num);
    ifx_platform_log_msg(out_buf, buf_size);

}
void print_msg(const char* msg) {
    static unsigned char out_buf[5000];
    int buf_size = sprintf((char*)out_buf, "%s", msg);
    ifx_platform_log_msg(out_buf, buf_size);

}

static uint32_t checksum32(const uint8_t *buf, size_t len)
{
    uint32_t sum = 0;
    while (len--) {
        sum += *buf++;
    }
    return sum;
}


#include "psa/crypto.h"
#include <string.h>

#define SHA256_SZ   32
#define SIG_MAX_SZ  72          /* ECDSA P-256 DER max */

/* A dummy ClientHello-like blob (64 bytes) */
static const uint8_t client_hello[] = {
    0x16, 0x03, 0x03, 0x00, 0x3C, 0x01, 0x00, 0x00,
    0x38, 0x03, 0x03, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x22, 0x22, 0x22, 0x22, 0x33, 0x33, 0x33, 0x33,
    0x44, 0x44, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55,
    0x66, 0x66, 0x66, 0x66, 0x77, 0x77, 0x77, 0x77,
    0x00, 0x00, 0x00, 0x2E, 0x00, 0x2C, 0x00, 0x0A,
    0x00, 0x14, 0x00, 0x12, 0x00, 0x13, 0x00, 0x09,
    0x00, 0x0A, 0x00, 0x0B, 0x00, 0x0C, 0x00, 0x0D
};

psa_status_t mtls_digest_sign_test(mbedtls_svc_key_id_t key_id)
{
    psa_status_t status;
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    uint8_t digest[SHA256_SZ];
    uint8_t sig[SIG_MAX_SZ];
    size_t sig_len;
    uint8_t pub[65];               /* uncompressed P-256 */
    size_t pub_len;

    /* 1. Hash the message -------------------------------------------------- */
    status = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (status != PSA_SUCCESS) return status;

    status = psa_hash_update(&op, client_hello, sizeof(client_hello));
    if (status != PSA_SUCCESS) goto hash_exit;

    status = psa_hash_finish(&op, digest, sizeof(digest), &pub_len);
    if (status != PSA_SUCCESS) goto hash_exit;

    /* 2. Sign the digest --------------------------------------------------- */
    status = psa_sign_hash(key_id,
                          PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
                          digest, sizeof(digest),
                          sig, sizeof(sig), &sig_len);
    if (status != PSA_SUCCESS) return status;

    /* 3. Export public key and verify the signature ------------------------ */
    status = psa_export_public_key(key_id, pub, sizeof(pub), &pub_len);
    if (status != PSA_SUCCESS) return status;

    psa_key_attributes_t pub_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&pub_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&pub_attr, 256);
    psa_set_key_usage_flags(&pub_attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&pub_attr, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));

    mbedtls_svc_key_id_t pub_id;
    status = psa_import_key(&pub_attr, pub, pub_len, &pub_id);
    psa_reset_key_attributes(&pub_attr);
    if (status != PSA_SUCCESS) return status;

    status = psa_verify_hash(pub_id,
                            PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
                            digest, sizeof(digest),
                            sig, sig_len);

    psa_destroy_key(pub_id);      /* clean up the transient public key */
    return status;

hash_exit:
    psa_hash_abort(&op);
    return status;
}

void key_test()
{
    enum {
        key_bits = 256,
    };
    psa_status_t status;
    size_t exported_length = 0;
    static uint8_t exported[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits)];
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_USER_MIN;

    print_msg("Generate a key pair...\t");

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        print_msg("Failed to initialize PSA Crypto\r\n");
        return;
    }
    status = psa_export_public_key(key_id, exported, sizeof(exported), &exported_length);
    if (status != PSA_SUCCESS) {
        /* Generate a key */
        psa_set_key_id(&attributes, key_id); 
        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
        psa_set_key_algorithm(&attributes,
                            PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
        psa_set_key_type(&attributes,
                        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&attributes, key_bits);
        status = psa_generate_key(&attributes, &key_id);
        print_num("Key id is %x\r\n", (int) key_id);
        if (status != PSA_SUCCESS) {
            print_msg("Failed to generate key\r\n");
            return;
        }
        psa_reset_key_attributes(&attributes);

        status = psa_export_public_key(key_id, exported, sizeof(exported),
                                    &exported_length);
    } else {
        print_msg("Key Exists\r\n");
    }
    if (status != PSA_SUCCESS) {
        print_num("Failed to export public key %ld\r\n", status) ;
        return;
    }

    print_msg("Exported a public key\r\n");
    print_num("Checksum=%d\r\n", (int) checksum32(exported, exported_length));

    mtls_digest_sign_test(key_id);


    /* Destroy the key */
//    psa_destroy_key(key_id);

    //mbedtls_psa_crypto_free();
}



/*******************************************************************************
* Function Name: main
********************************************************************************
* Summary:
* This is the main function of the CM33 non-secure application. 
*
* It initializes the TF-M NS interface to communicate with TF-M FW. The app
* calls PSA APIs to use the Internal Trusted Storage secure services
* offered by TF-M.

* Parameters:
*  none
*
* Return:
*  int
*
*******************************************************************************/

int _write(int fd, const void *buf, size_t count) {
    return (int) ifx_platform_log_msg((const uint8_t*)buf, count);
}

void psa_test(void)
{
    cy_rslt_t result;
    uint32_t rslt;
    char set_data[] = "Hello World";
    char get_data[ITS_BUFF_SIZE] = {0};
    size_t get_len = 0;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    unsigned char out_buf[256];
    int buf_size;

    /* Initialize the device and board peripherals */
#if 0
    result = cybsp_init();

    /* Board init failed. Stop program execution */
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Enable global interrupts */
    __enable_irq();

    /* Initialize retarget-io middleware */
    // init_retarget_io();

#endif
    /* Initialize TF-M interface */
    rslt = tfm_ns_interface_init();

    if(rslt != OS_WRAPPER_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* \x1b[2J\x1b[;H - ANSI ESC sequence for clear screen */
    buf_size = sprintf((char*)out_buf, "\x1b[2J\x1b[;H"
                "******* "
                "PSOC Edge MCU: Basic Trusted Firmware-M (TF-M) based Application "
                "******* \r\n\n");
    ifx_platform_log_msg(out_buf, buf_size);


    buf_size = sprintf((char*)out_buf, "*** TF-M Internal Trusted Storage (ITS) service ***\r\n\n");
    ifx_platform_log_msg(out_buf, buf_size);

    buf_size = sprintf((char*)out_buf, "ITS Storage data: %s\r\n", set_data);
    ifx_platform_log_msg(out_buf, buf_size);

    buf_size = sprintf((char*)out_buf, "Storing data in ITS...\r\n\n");
    ifx_platform_log_msg(out_buf, buf_size);

    /* Start of Internal Trusted Storage code.
     * Internal Trusted Storage can store upto 10 assets. The maximum size of asset
     * can be upto 512 bytes.
     */
    status = psa_its_set(ITS_UID, sizeof(set_data), set_data, PSA_STORAGE_FLAG_NONE);
    if(status != PSA_SUCCESS)
    {
        CY_ASSERT(0);
    }

    buf_size = sprintf((char*)out_buf, "Retrieving data from ITS...\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    status = psa_its_get(ITS_UID, 0, sizeof(set_data), get_data, &get_len);
    if(status != PSA_SUCCESS)
    {
        CY_ASSERT(0);
    }

    buf_size = sprintf((char*)out_buf, "Retrieved data: %s\r\n\n", get_data);
    ifx_platform_log_msg(out_buf, buf_size);

    key_test();

#if 0

    /* End of Internal Trusted Storage code */

    /* Enable CM55. */
    /* CY_CM55_APP_BOOT_ADDR must be updated if CM55 memory layout is changed.*/
    Cy_SysEnableCM55(MXCM55, CM55_APP_BOOT_ADDR, CM55_BOOT_WAIT_TIME_USEC);

    for (;;)
    {

        /* Receive and forward the IPC requests from M55 to TF-M. 
         * M55 can request security aware PDL and TF-M for secure services,
         * and these requests are sent from M55 to M33 NS using Secure Request
         * Framework (SRF) over IPC.
         */
        result = mtb_srf_ipc_receive_request(&cybsp_mtb_srf_relay_context, MTB_IPC_NEVER_TIMEOUT);
        if(result != CY_RSLT_SUCCESS)
        {
            CY_ASSERT(0);
        }
        result =  mtb_srf_ipc_process_pending_request(&cybsp_mtb_srf_relay_context);
        if(result != CY_RSLT_SUCCESS)
        {
            CY_ASSERT(0);
        }
    }
#endif
}

void psa_test_task(void *pvParameters) {
    (void) pvParameters;

    psa_test();

    while (true) {
        taskYIELD();
    }

}
/* [] END OF FILE */
