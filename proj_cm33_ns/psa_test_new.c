#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "psa/crypto.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pem.h"
#include "cy_tcpip_port_secure_sockets.h"
#include "cy_syslib.h"
#include "psa/crypto_values.h"
#include "psa/internal_trusted_storage.h"
#include "mbedtls/ecdsa.h"

// for TFM
#include "tfm_ns_interface.h"
#include "os_wrapper/common.h"


#define PSA_MQTT_KEY_ID (5U)
#define CRT_DER_ITS_UID (5U)
#define CRT_DER_DATA_SIZE (512) // as much as PSA will allow us to store

static psa_key_id_t key_id = PSA_KEY_ID_NULL;
static char crt_pem_buffer[1024]; // For printing PEM

/* Header for fields that precede the buffer. Keep in sync with members used
   elsewhere. */
typedef struct {
    uint8_t version;
    uint8_t padding;
    uint16_t size;
} crt_der_header_t;

/* Final struct sized to CRT_DER_DATA_SIZE bytes. The array length is computed
   from the header size so changes to the header are accounted for. */
typedef struct crt_der_data_t {
    crt_der_header_t hdr;
    uint8_t buff[CRT_DER_DATA_SIZE - sizeof(crt_der_header_t)];
} crt_der_data_t;

_Static_assert(sizeof(crt_der_data_t) == CRT_DER_DATA_SIZE,
               "crt_der_data_t must be CRT_DER_DATA_SIZE bytes");

/* Validate PSA key and destroy if invalid */
bool validate_key(psa_key_id_t key_id) {
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status = psa_get_key_attributes(key_id, &attributes);
    if (status != PSA_SUCCESS) return false;  // key doesn't exist
    if (psa_get_key_type(&attributes) == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) &&
        psa_get_key_algorithm(&attributes) == PSA_ALG_ECDSA(PSA_ALG_SHA_256) &&
        (psa_get_key_usage_flags(&attributes) & PSA_KEY_USAGE_SIGN_HASH) &&
        psa_get_key_lifetime(&attributes) == PSA_KEY_LIFETIME_PERSISTENT &&
        psa_get_key_bits(&attributes) == 256
    ) {
        return true;
    } else {
        psa_destroy_key(key_id);
        printf("PSA: Destroyed invalid key %x\n", (int)key_id);
        return false;
    }
}

/* Setup PSA key and certificate for MQTT */
void psa_mqtt_setup(void) {
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    /* Initialize TF-M interface */
    if (0 != tfm_ns_interface_init()) {
        printf("tfm_ns_interface_init failed!\n");
    }


    if (key_id != PSA_KEY_ID_NULL) {
        printf("Double call to psa_mqtt_setup\n");
        return;
    }
    
    /* Clear ITS and key for testing as needed */
    #if 0
    // leftover by other tests:
    psa_its_remove(1U);
    psa_destroy_key(9U);
    // the actuals:
    psa_its_remove(CRT_DER_ITS_UID);
    psa_destroy_key(PSA_MQTT_KEY_ID);
    printf("##########    KEY FORCEFULLY RECREATED    ############\n");
    #endif

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("PSA crypto init failed: 0x%lx\n", (long)status);
        return;
    }

    /* Malloc cert DER data buffer */
    crt_der_data_t* der_data = malloc(sizeof(crt_der_data_t));

    if (!der_data) {
        printf("Failed to malloc DER cert data\n");
        goto error_cleanup;
    }

    /* Mark version so future upgrades can be handled */
    der_data->hdr.version = 1;

    if (validate_key(PSA_MQTT_KEY_ID)) {

        /* Try to load existing cert from ITS */
        size_t get_size = 0;
        status = psa_its_get(CRT_DER_ITS_UID, 0, sizeof(crt_der_data_t), der_data, &get_size);
        if (status == PSA_SUCCESS && get_size > 0) {
            printf("PSA: Loaded existing cert from ITS. %d total data. cert size %d.\n", (int)get_size, der_data->hdr.size);
        } else {
            printf("PSA: Failed to load the cert from ITS. Error: %d\n", (int) status);
        }

        /* Convert DER to PEM for printing */
        size_t bytes_written_or_required;
        int pem_ret = mbedtls_pem_write_buffer(
            "-----BEGIN CERTIFICATE-----\n",
            "-----END CERTIFICATE-----\n",
            der_data->buff, der_data->hdr.size,
            (unsigned char*)crt_pem_buffer, sizeof(crt_pem_buffer) - 1, &bytes_written_or_required
        );
        free(der_data); // done with the buffer
        der_data = NULL;

        if (pem_ret == 0) {
            // make sure to null-terminate on success. I think the call will not do it
            crt_pem_buffer[bytes_written_or_required] = '\0';
            printf("Loaded Certificate (PEM):\n%s\n", crt_pem_buffer);
        } else {
            printf("Failed to convert DER to PEM for printing. Error was %d\n", pem_ret);
            goto error_cleanup;
        }
    } else {
        printf("PSA: No cert in ITS, will generate new one\n");

        printf("PSA: Generating new key...\n");

        psa_set_key_id(&attributes, PSA_MQTT_KEY_ID);
        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
        psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
        psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&attributes, 256);
        status = psa_generate_key(&attributes, &key_id);
        if (status != PSA_SUCCESS) {
            printf("PSA key generation failed: 0x%lx\n", (long)status);
            goto error_cleanup;
        }

        psa_reset_key_attributes(&attributes);

        printf("PSA: Key generated, ID=%d\n", (int)key_id);

        key_id = PSA_MQTT_KEY_ID;

        mbedtls_pk_context pk_context;
        mbedtls_pk_init(&pk_context);
        status = mbedtls_pk_setup_opaque(&pk_context, key_id);
        /* Setup MbedTLS PK context */
        if (status != PSA_SUCCESS) {
            printf("mbedtls_pk_setup_opaque failed: 0x%lx\n", (long)status);
            mbedtls_pk_free(&pk_context);
            goto error_cleanup;
        }

        /* Generate cert */
        extern int generate_selfsigned_cert_psa(mbedtls_pk_context *key, unsigned char* pem_buffer, size_t der_buffer_or_ret_size);
        der_data->hdr.size = sizeof(der_data->buff);
        int cert_ret = generate_selfsigned_cert_psa(&pk_context, der_data->buff, sizeof(der_data->buff));
            if (cert_ret < 0) {
                printf("Certificate generation failed: %d\n", cert_ret);
                mbedtls_pk_free(&pk_context);
                goto error_cleanup;
            }
        der_data->hdr.size = cert_ret;

        status = psa_its_set(CRT_DER_ITS_UID, sizeof(crt_der_data_t), der_data, PSA_STORAGE_FLAG_NONE);
        if (status != PSA_SUCCESS) {
            printf("Failed to store cert in ITS: 0x%d\n", (int) status);
            mbedtls_pk_free(&pk_context);
            goto error_cleanup;
        } else {
            printf("PSA: Cert stored in ITS\n");
        }
        mbedtls_pk_free(&pk_context);

        /* Convert DER to PEM for printing */
        size_t bytes_written_or_required;
        int pem_ret = mbedtls_pem_write_buffer(
            "-----BEGIN CERTIFICATE-----\n",
            "-----END CERTIFICATE-----\n",
            der_data->buff, der_data->hdr.size,
            (unsigned char*)crt_pem_buffer, sizeof(crt_pem_buffer) - 1, &bytes_written_or_required
        );
        free(der_data); // done with the buffer
        der_data = NULL;

        if (pem_ret == 0) {
            // make sure to null-terminate on success. I think the call will not do it
            crt_pem_buffer[bytes_written_or_required] = '\0';
            printf("Loaded Certificate (PEM):\n%s\n", crt_pem_buffer);
            free(der_data); // done with the buffer
            der_data = NULL;            
            /* keep der_data around so we can store it to ITS below */
        } else {
            printf("Failed to convert DER to PEM for printing. Error was %d\n", pem_ret);
            goto error_cleanup;
        }
    }

    return;

error_cleanup:
    key_id = PSA_KEY_ID_NULL;
    psa_its_remove(CRT_DER_ITS_UID);
    psa_destroy_key(PSA_MQTT_KEY_ID);
    if (der_data) {
        free(der_data);
    }

}

/* Configure security_info with PSA cert and opaque key */
void psa_mqtt_inject_credentials(cy_awsport_ssl_credentials_t *sec_info) {

    if (sec_info == NULL) {
        printf("Error: sec_info is NULL!\n");
        return;
    }
    if (key_id == PSA_KEY_ID_NULL) {
        printf("Error: PSA MQTT credentials not initialized\n");
        sec_info->client_cert = NULL;
        sec_info->client_cert_size = 0;
        sec_info->private_key = NULL;
        sec_info->private_key_size = 0;
        return;
    }

    sec_info->client_cert = (const char *)crt_pem_buffer;
    sec_info->client_cert_size = strlen((char*)crt_pem_buffer) + 1;
    sec_info->private_key = (const char *)&key_id;
    sec_info->private_key_size = sizeof(psa_key_id_t);
}

/* Dummy ALT implementation for ECDSA sign - removed since not using ALT */