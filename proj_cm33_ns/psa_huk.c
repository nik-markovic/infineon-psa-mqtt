/* psa_huk.c - HUK-derived volatile key + ITS-stored deterministic certificate
 * Decision based ONLY on certificate presence in ITS slot 8
 * Uses original gencert.c as-is
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "psa/crypto.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pem.h"
#include "cy_tcpip_port_secure_sockets.h"
#include "psa/internal_trusted_storage.h"
// for TFM
#include "tfm_ns_interface.h"

/* Isolated function to test PSA algorithm support */
void test_psa_algorithms();

/* Configuration */
#define HUK_KEY_ID          ((psa_key_id_t)0x7FFF0000U)   // Factory test key - die-unique, always accessible
#define CRT_DER_ITS_UID     (8U)                          // New ITS slot for certificate
#define CRT_DER_DATA_SIZE   (512)

/* Global state */
static psa_key_id_t key_id = PSA_KEY_ID_NULL;
static char crt_pem_buffer[1024] = {0};

/* Structure for stored certificate */
typedef struct {
    uint8_t version;
    uint8_t padding;
    uint16_t size;
} crt_der_header_t;

typedef struct {
    crt_der_header_t hdr;
    uint8_t buff[CRT_DER_DATA_SIZE - sizeof(crt_der_header_t)];
} crt_der_data_t;

/* External original cert generator */
extern int generate_selfsigned_cert_psa(mbedtls_pk_context *key,
                                        unsigned char* der_buffer,
                                        size_t der_buffer_len);

/* Setup PSA key and certificate for MQTT */
void psa_mqtt_setup_huk(void)
{
    psa_status_t status;
    crt_der_data_t* der_data = NULL;

    if (key_id != PSA_KEY_ID_NULL) {
        printf("PSA_HUK: Already initialized\n");
        return;
    }

    if (tfm_ns_interface_init() != 0) {
        printf("tfm_ns_interface_init failed!\n");
        return;
    }

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("PSA crypto init failed: 0x%lx\n", (unsigned long)status);
        return;
    }

    der_data = malloc(sizeof(crt_der_data_t));
    if (!der_data) {
        printf("Failed to malloc DER buffer\n");
        goto error_cleanup;
    }
    der_data->hdr.version = 1;

    /* ------------------- Check if certificate exists in ITS ------------------- */
    size_t get_size = 0;
    status = psa_its_get(CRT_DER_ITS_UID, 0, sizeof(crt_der_data_t), der_data, &get_size);

    if (status == PSA_SUCCESS && get_size >= sizeof(crt_der_header_t) && der_data->hdr.version == 1) {
        printf("PSA_HUK: Certificate found in ITS slot 8, size=%d\n", der_data->hdr.size);

        /* Derive volatile key from HUK (always done) */
        psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
        status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
        if (status != PSA_SUCCESS) goto error_cleanup;

        status = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, HUK_KEY_ID);
        if (status != PSA_SUCCESS) {
            printf("HUK access failed: 0x%lx\n", (unsigned long)status);
            psa_key_derivation_abort(&op);
            goto error_cleanup;
        }

        status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                                (const uint8_t*)"Avnet IoTConnect P256R1 Client v1", 41);
        if (status != PSA_SUCCESS) {
            psa_key_derivation_abort(&op);
            goto error_cleanup;
        }

        psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&attrs, 256);
        psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_HASH);
        psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
        psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

        status = psa_key_derivation_output_key(&attrs, &op, &key_id);
        psa_key_derivation_abort(&op);
        if (status != PSA_SUCCESS) {
            printf("HUK derivation failed: 0x%lx\n", (unsigned long)status);
            goto error_cleanup;
        }

        /* Convert stored DER to PEM for printing */
        size_t pem_len;
        int ret = mbedtls_pem_write_buffer(
            "-----BEGIN CERTIFICATE-----\n",
            "-----END CERTIFICATE-----\n",
            der_data->buff, der_data->hdr.size,
            (unsigned char*)crt_pem_buffer,
            sizeof(crt_pem_buffer)-1, &pem_len
        );
        free(der_data);
        der_data = NULL;
        if (ret == 0) {
            crt_pem_buffer[pem_len] = '\0';
            printf("Loaded Certificate (PEM):\n%s\n", crt_pem_buffer);
        } else {
            printf("PEM conversion failed: %d\n", ret);
            goto error_cleanup;
        }
    }
    /* ------------------- No cert in ITS → generate once and store ------------------- */
    else {
        printf("PSA_HUK: No certificate in ITS, generating new identity...\n");

        /* Derive volatile key from HUK */
        psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
        status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
        if (status != PSA_SUCCESS) goto error_cleanup;

        status = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, HUK_KEY_ID);
        if (status != PSA_SUCCESS) {
            printf("HUK access failed: 0x%lx\n", (unsigned long)status);
            psa_key_derivation_abort(&op);
            goto error_cleanup;
        }

        status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                                (const uint8_t*)"Avnet IoTConnect P256R1 Client v1", 41);
        if (status != PSA_SUCCESS) {
            psa_key_derivation_abort(&op);
            goto error_cleanup;
        }

        psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&attrs, 256);
        psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_HASH);
        psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
        psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

        status = psa_key_derivation_output_key(&attrs, &op, &key_id);
        psa_key_derivation_abort(&op);
        if (status != PSA_SUCCESS) {
            printf("HUK derivation failed: 0x%lx\n", (unsigned long)status);
            goto error_cleanup;
        }

        /* Generate certificate using original function */
        mbedtls_pk_context pk_context;
        mbedtls_pk_init(&pk_context);
        status = mbedtls_pk_setup_opaque(&pk_context, key_id);
        if (status != PSA_SUCCESS) {
            printf("mbedtls_pk_setup_opaque failed: 0x%lx\n", (unsigned long)status);
            mbedtls_pk_free(&pk_context);
            goto error_cleanup;
        }

        der_data->hdr.size = sizeof(der_data->buff);
        int cert_ret = generate_selfsigned_cert_psa(&pk_context,
                                                    der_data->buff,
                                                    sizeof(der_data->buff));
        mbedtls_pk_free(&pk_context);
        if (cert_ret < 0) {
            printf("Certificate generation failed: %d\n", cert_ret);
            goto error_cleanup;
        }
        der_data->hdr.size = cert_ret;

        status = psa_its_set(CRT_DER_ITS_UID, sizeof(crt_der_data_t), der_data, PSA_STORAGE_FLAG_NONE);
        if (status != PSA_SUCCESS) {
            printf("Failed to store cert in ITS slot 8: 0x%lx\n", (unsigned long)status);
            goto error_cleanup;
        }
        printf("PSA_HUK: Certificate generated and stored in ITS slot 8\n");

        /* Convert and print */
        size_t pem_len;
        int ret = mbedtls_pem_write_buffer(
            "-----BEGIN CERTIFICATE-----\n",
            "-----END CERTIFICATE-----\n",
            der_data->buff, der_data->hdr.size,
            (unsigned char*)crt_pem_buffer,
            sizeof(crt_pem_buffer)-1, &pem_len
        );
        free(der_data);
        der_data = NULL;
        if (ret == 0) {
            crt_pem_buffer[pem_len] = '\0';
            printf("Generated Certificate (PEM):\n%s\n", crt_pem_buffer);
        } else {
            printf("PEM conversion failed: %d\n", ret);
            goto error_cleanup;
        }
    }

    printf("PSA_HUK: Ready - volatile HUK-derived key + persistent cert\n");
    return;

error_cleanup:
    if (der_data) free(der_data);
    key_id = PSA_KEY_ID_NULL;
    psa_its_remove(CRT_DER_ITS_UID);
}

/* Configure security_info with PSA cert and opaque key */
void psa_mqtt_inject_credentials(cy_awsport_ssl_credentials_t *sec_info)
{
    if (!sec_info) {
        printf("Error: sec_info is NULL!\n");
        return;
    }
    if (key_id == PSA_KEY_ID_NULL) {
        printf("Error: PSA HUK credentials not initialized\n");
        return;
    }

    sec_info->client_cert = (const char *)crt_pem_buffer;
    sec_info->client_cert_size = strlen(crt_pem_buffer) + 1;
    sec_info->private_key = (const char *)&key_id;
    sec_info->private_key_size = sizeof(psa_key_id_t);
    sec_info->root_ca_verify_mode = CY_AWS_ROOTCA_VERIFY_NONE;
}