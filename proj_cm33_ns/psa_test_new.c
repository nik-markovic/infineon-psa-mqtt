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


/* Isolated function to test PSA algorithm support */
void test_psa_algorithms();


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
        (psa_get_key_usage_flags(&attributes) & (PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_DERIVE)) &&
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
    
    #if 0
    /* Clear ITS and key for testing as needed */
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
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_DERIVE);
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
        } else {
            printf("Failed to convert DER to PEM for printing. Error was %d\n", pem_ret);
            goto error_cleanup;
        }
    }
    
    // everything worked. Key can be used.
    key_id = PSA_MQTT_KEY_ID;

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

    // TEMP: Test PSA support
    test_psa_algorithms();

    if (sec_info == NULL) {
        printf("Error: sec_info is NULL!\n");
        return;
    }
    if (key_id == PSA_KEY_ID_NULL) {
        printf("Error: PSA MQTT credentials not initialized\n");
        return;
    }
    sec_info->client_cert = (const char *)crt_pem_buffer;
    sec_info->client_cert_size = strlen((char*)crt_pem_buffer) + 1;
    sec_info->private_key = (const char *)&key_id;
    sec_info->private_key_size = sizeof(psa_key_id_t);

    // TEMP HACK
    sec_info->root_ca_verify_mode = CY_AWS_ROOTCA_VERIFY_NONE;
}

/* Dummy ALT implementation for ECDSA sign - removed since not using ALT */

/* Isolated function to test PSA algorithm support with iterations */
void test_psa_algorithms() {
    typedef struct {
        const char *name;
        psa_key_lifetime_t lifetime;
        psa_key_usage_t usage;
        psa_algorithm_t alg;
        psa_key_type_t type;
        size_t bits;
    } test_case_t;

    test_case_t tests[] = {
        {"Volatile EC Sign", PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_USAGE_SIGN_HASH, PSA_ALG_ECDSA(PSA_ALG_SHA_256), PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256},
        {"Volatile EC Derive", PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256},
        {"Volatile EC Sign+Derive", PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDSA(PSA_ALG_SHA_256), PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256},
        {"Persistent EC Sign", PSA_KEY_LIFETIME_PERSISTENT, PSA_KEY_USAGE_SIGN_HASH, PSA_ALG_ECDSA(PSA_ALG_SHA_256), PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256},
        {"Volatile RSA Sign/Verify (PKCS#1 v1.5)", PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256), PSA_KEY_TYPE_RSA_KEY_PAIR, 2048},
    };

    psa_status_t status;
    psa_key_id_t test_key_id;
    size_t num_tests = sizeof(tests) / sizeof(test_case_t);

    printf("=== PSA Support Test (Iterative) ===\n");

    status = psa_crypto_init();
    printf("PSA Init: %ld\n", (long)status);
    if (status != PSA_SUCCESS) return;

    for (size_t i = 0; i < num_tests; i++) {
        test_case_t *tc = &tests[i];
        psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

        printf("\nTest %d: %s\n", (int) i, tc->name);

        psa_set_key_lifetime(&attr, tc->lifetime);
        psa_set_key_usage_flags(&attr, tc->usage);
        psa_set_key_algorithm(&attr, tc->alg);
        psa_set_key_type(&attr, tc->type);
        psa_set_key_bits(&attr, tc->bits);
        if (tc->lifetime == PSA_KEY_LIFETIME_PERSISTENT) {
            psa_destroy_key(9U);
            psa_set_key_id(&attr, 9U);
        }

        status = psa_generate_key(&attr, &test_key_id);
        printf("  Generate Key: %ld\n", (long)status);

        if (status == PSA_SUCCESS) {
            if (tc->usage & PSA_KEY_USAGE_SIGN_HASH) {
                uint8_t sig[256];
                size_t sig_len;
                uint8_t digest[32] = {0};
                status = psa_sign_hash(test_key_id, tc->alg, digest, sizeof(digest), sig, sizeof(sig), &sig_len);
                printf("  Sign: %ld\n", (long)status);
                if (status == PSA_SUCCESS) {
                    // Test verify
                    status = psa_verify_hash(test_key_id, tc->alg, digest, sizeof(digest), sig, sig_len);
                    printf("  Verify: %ld\n", (long)status);
                }
            }

            if (tc->usage & PSA_KEY_USAGE_VERIFY_HASH && tc->type == PSA_KEY_TYPE_RSA_KEY_PAIR) {
                // RSA verification test - sign with same key and verify
                uint8_t sig[256];
                size_t sig_len;
                uint8_t digest[32] = {0};
                status = psa_sign_hash(test_key_id, tc->alg, digest, sizeof(digest), sig, sizeof(sig), &sig_len);
                printf("  RSA Sign: %ld\n", (long)status);
                if (status == PSA_SUCCESS) {
                    status = psa_verify_hash(test_key_id, tc->alg, digest, sizeof(digest), sig, sig_len);
                    printf("  RSA Verify: %ld\n", (long)status);
                }
            }

            if (tc->usage & PSA_KEY_USAGE_DERIVE && tc->alg == PSA_ALG_ECDH) {
                // Simple ECDH test with valid dummy peer public key (secp256r1 uncompressed)
                uint8_t shared[32];
                size_t secret_len;
                uint8_t dummy_peer[65] = {
                    0x04, // uncompressed
                    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
                    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
                    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
                    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
                };
                status = psa_raw_key_agreement(tc->alg, test_key_id, dummy_peer, sizeof(dummy_peer), shared, sizeof(shared), &secret_len);
                printf("  ECDH: %ld\n", (long)status);
            }

            if (tc->alg == PSA_ALG_GCM) {
                // Test AES GCM encryption
                uint8_t plaintext[16] = "Hello AES GCM!";
                uint8_t ciphertext[16 + 16]; // + tag
                size_t ciphertext_len;
                uint8_t nonce[12] = {0};
                uint8_t aad[0]; // no AAD
                status = psa_aead_encrypt(test_key_id, tc->alg, nonce, sizeof(nonce), aad, sizeof(aad), plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext), &ciphertext_len);
                printf("  AES GCM Encrypt: %ld\n", (long)status);
            }

            psa_destroy_key(test_key_id);
        }
    }

    printf("\n=== End PSA Support Test ===\n");
}