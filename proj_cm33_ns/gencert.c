/* SPDX-License-Identifier: MIT
 * Copyright (C) 2024 Avnet
 * Authors: Nikola Markovic <nikola.markovic@avnet.com>
 */

#include <stdio.h>
#include <string.h>
#include "cy_syslib.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#ifndef IOTC_GENCRT_NOT_BEFORE
#define IOTC_GENCRT_NOT_BEFORE          "20250101000000"
#endif

#ifndef IOTC_GENCRT_NOT_AFTER
#define IOTC_GENCRT_NOT_AFTER           "20500101000000"
#endif

#ifndef IOTC_GENCRT_SIGN_ALG
#define IOTC_GENCRT_SIGN_ALG            MBEDTLS_MD_SHA256
#endif

#ifndef IOTC_GENCRT_SUBJECT_NAME
#define IOTC_GENCRT_SUBJECT_NAME        "CN=IoTConnectDevCert,O=Avnet,C=US"
#endif

// Adapted for PSA opaque keys
int generate_selfsigned_cert_psa(mbedtls_pk_context *key, unsigned char* der_buffer, size_t der_buffer_len) {
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
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)"psa_cert_gen", 12);
    if (ret != 0) {
        printf("DRBG seed failed: %d\n", ret);
        goto exit;
    }

    /* Set serial number using hardware unique ID */
    uint64_t hwuid = Cy_SysLib_GetUniqueId();
    if (hwuid == 0) hwuid = 1; /* Fallback if unique ID is 0 */
    printf("HWUID: 0x%llx\n", (unsigned long long)hwuid);
    ret = mbedtls_x509write_crt_set_serial_raw(&crt, (unsigned char *)&hwuid, sizeof(hwuid));
    if (ret != 0) {
        printf("Failed to set cert serial: %d\n", ret);
        goto exit;
    }

    /* Set subject and issuer keys (returns void) */
    mbedtls_x509write_crt_set_subject_key(&crt, key);
    mbedtls_x509write_crt_set_issuer_key(&crt, key);

    /* Set subject and issuer names */
    ret = mbedtls_x509write_crt_set_subject_name(&crt, IOTC_GENCRT_SUBJECT_NAME);
    if (ret != 0) {
        printf("Failed to set subject name: %d\n", ret);
        goto exit;
    }
    ret = mbedtls_x509write_crt_set_issuer_name(&crt, IOTC_GENCRT_SUBJECT_NAME);
    if (ret != 0) {
        printf("Failed to set issuer name: %d\n", ret);
        goto exit;
    }

    /* Set version and signature algorithm */
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, IOTC_GENCRT_SIGN_ALG);

    /* Set validity */
    ret = mbedtls_x509write_crt_set_validity(&crt, IOTC_GENCRT_NOT_BEFORE, IOTC_GENCRT_NOT_AFTER);
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

    /* Write to DER */
    ret = mbedtls_x509write_crt_der(&crt, der_buffer, der_buffer_len,
        mbedtls_ctr_drbg_random, &ctr_drbg
    );
    if (ret < 0) {
        printf("Failed to write cert DER: %d\n", ret);
        goto exit;
    }
    printf("Cert DER Size: %d\n", ret);

    /* DER is written to the end of the buffer, move to beginning */
    memmove(der_buffer, der_buffer + der_buffer_len - ret, ret);

    printf("PSA: Certificate generated, size=%d\n", ret);
    // DER is binary, no PEM print
    // ret already has the size

exit:
    mbedtls_mpi_free(&serial);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509write_crt_free(&crt);
    return ret;
}