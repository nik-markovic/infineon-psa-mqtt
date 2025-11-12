/*
 * Minimal secure-side PSA crypto overlay for this project.
 * Includes the base TF-M medium profile and then enables AES-GCM
 * to satisfy TLS AEAD requirements for AWS IoT (ECDHE-ECDSA-AES-GCM).
 */
#ifndef PSA_CRYPTO_CONFIG_OVERLAY_H
#define PSA_CRYPTO_CONFIG_OVERLAY_H

/* Include the base profile config used by TF-M on this target. */
#include "C:/iotconnect/p-tfm-mqtt/mtb_shared/ifx-tf-m-pse84epc2/release-v2.1.400/src/lib/ext/mbedcrypto/mbedcrypto_config/crypto_config_profile_medium.h"

/* Additive enablement: turn on GCM (AES key type is already enabled in base). */
#ifndef PSA_WANT_ALG_GCM
#define PSA_WANT_ALG_GCM 1
#endif

#endif /* PSA_CRYPTO_CONFIG_OVERLAY_H */
