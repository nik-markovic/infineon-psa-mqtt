#include <stdio.h>
#include <string.h>
#include "psa/crypto.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "cy_tcpip_port_secure_sockets.h"

#include "mbedtls/ecdsa.h"

#define PSA_MQTT_KEY_ID (1U)
#define CERT_BUFFER_SIZE (4096)

static uint8_t g_cert_buffer[CERT_BUFFER_SIZE];
static size_t g_cert_size = 0;
static mbedtls_pk_context g_pk_context;
static psa_key_id_t g_key_id;
static int g_initialized = 0;

/* Generate self-signed cert using PSA key for signing (based on iotc_gencert.c pattern) */
static int psa_generate_selfsigned_cert(mbedtls_pk_context *key)
{
    int ret = 1;
    mbedtls_mpi serial;
    mbedtls_x509write_cert crt;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    mbedtls_mpi_init(&serial);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509write_crt_init(&crt);

    /* Initialize DRBG for cert generation */
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0) {
        printf("DRBG seed failed: %d\n", ret);
        goto exit;
    }

    /* Set serial number */
    ret = mbedtls_x509write_crt_set_serial_raw(&crt, (unsigned char *)&g_pk_context, sizeof(uintptr_t));
    if (ret != 0) {
        printf("Failed to set cert serial: %d\n", ret);
        goto exit;
    }

    /* Set subject and issuer keys (returns void) */
    mbedtls_x509write_crt_set_subject_key(&crt, key);
    mbedtls_x509write_crt_set_issuer_key(&crt, key);

    /* Set version and signature algorithm */
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

    /* Set validity */
    ret = mbedtls_x509write_crt_set_validity(&crt, "20000101000000Z", "30991231235959Z");
    if (ret != 0) {
        printf("Failed to set validity: %d\n", ret);
        goto exit;
    }

    /* Set basic constraints */
    ret = mbedtls_x509write_crt_set_basic_constraints(&crt, 1, 0);
    if (ret != 0) {
        printf("Failed to set constraints: %d\n", ret);
        goto exit;
    }

    /* Write to PEM */
    ret = mbedtls_x509write_crt_pem(&crt, g_cert_buffer, CERT_BUFFER_SIZE,
                                     mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret < 0) {
        printf("Failed to write cert PEM: %d\n", ret);
        goto exit;
    }

    g_cert_size = ret;
    printf("PSA: Certificate generated, size=%zu\n", g_cert_size);
    printf("Generated Certificate (PEM):\n%s\n", g_cert_buffer);
    ret = 0;

exit:
    mbedtls_mpi_free(&serial);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509write_crt_free(&crt);
    return ret;
}

/* Setup PSA key and certificate for MQTT */
void psa_mqtt_setup(void)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_MQTT_KEY_ID;
    uint8_t exported[65];
    size_t exported_len = 0;

    if (g_initialized) {
        return;
    }

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("PSA crypto init failed: 0x%lx\n", (long)status);
        return;
    }

    /* Try to export existing key */
    status = psa_export_public_key(key_id, exported, sizeof(exported), &exported_len);
    if (status != PSA_SUCCESS) {
        /* Key doesn't exist, generate new one */
        printf("PSA: Generating new key...\n");

        psa_set_key_id(&attributes, key_id);
        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE);
        psa_set_key_algorithm(&attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
        psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&attributes, 256);

        status = psa_generate_key(&attributes, &key_id);
        psa_reset_key_attributes(&attributes);

        if (status != PSA_SUCCESS) {
            printf("PSA key generation failed: 0x%lx\n", (long)status);
            return;
        }
        printf("PSA: Key generated, ID=%lu\n", (long unsigned)key_id);
        g_key_id = key_id;
    } else {
        printf("PSA: Using existing key (pub_len=%zu)\n", exported_len);
        g_key_id = key_id;
    }

    /* Setup MbedTLS PK context to use PSA key (opaque - private key never exposed) */
    mbedtls_pk_init(&g_pk_context);
    status = mbedtls_pk_setup_opaque(&g_pk_context, key_id);
    if (status != PSA_SUCCESS) {
        printf("mbedtls_pk_setup_opaque failed: 0x%lx\n", (long)status);
        return;
    }

    /* Generate self-signed certificate */
    if (psa_generate_selfsigned_cert(&g_pk_context) != 0) {
        printf("Certificate generation failed\n");
        mbedtls_pk_free(&g_pk_context);
        return;
    }

    g_initialized = 1;
    printf("PSA MQTT setup complete\n");
}

/* Configure security_info with PSA cert and opaque key */
void psa_mqtt_configure(cy_awsport_ssl_credentials_t *sec_info)
{
    /* Setup PSA key and cert if not already done */
    psa_mqtt_setup();

    if (sec_info != NULL) {
        sec_info->client_cert = (const char *)g_cert_buffer;
        sec_info->client_cert_size = g_cert_size;
        sec_info->private_key = (const char *)&g_key_id;
        sec_info->private_key_size = sizeof(psa_key_id_t);
    }
}

/* Dummy ALT implementation for ECDSA sign - removed since not using ALT */