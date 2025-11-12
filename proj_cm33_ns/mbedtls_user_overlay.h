#ifndef MBEDTLS_USER_OVERLAY_HEADER
#define MBEDTLS_USER_OVERLAY_HEADER

#include "configs/mbedtls_user_config.h"

// We apply our overrides here:
// Certificate creation and handling for self-signed cert generation
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_X509_CRT_WRITE_C

// PSA-based key data: Store EC keys as PSA opaque keys (PSA key handles instead of raw key material)
// This ensures private keys are never exposed in user-space memory
#define MBEDTLS_PK_USE_PSA_EC_DATA

#include "configs/mbedtls_user_config.h"

// We apply our overrides here:
// Certificate creation and handling for self-signed cert generation
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_X509_CRT_WRITE_C

// PSA-based key data: Store EC keys as PSA opaque keys (PSA key handles instead of raw key material)
// This ensures private keys are never exposed in user-space memory
#define MBEDTLS_PK_USE_PSA_EC_DATA

// Enable ALT signing to override ECDSA sign with PSA call
// #define MBEDTLS_ECDSA_SIGN_ALT  // Removed to avoid library conflicts; use existing opaque PSA flow instead

// These should be defacto for PSA. 
// From mtb_shared\wifi-core-freertos-lwip-mbedtls\release-v3.1.0\configs\mbedtls_user_config.h:
// NOTE: 25519 could have issues with some HTTPS servers. Migth be good to remove it as well if it is active.
#undef MBEDTLS_ECP_DP_SECP192R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP224R1_ENABLED
//#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP384R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP521R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP192K1_ENABLED
#undef MBEDTLS_ECP_DP_SECP224K1_ENABLED
#undef MBEDTLS_ECP_DP_SECP256K1_ENABLED
#undef MBEDTLS_ECP_DP_BP256R1_ENABLED
#undef MBEDTLS_ECP_DP_BP384R1_ENABLED
#undef MBEDTLS_ECP_DP_BP512R1_ENABLED
#undef MBEDTLS_ECP_DP_CURVE25519_ENABLED
#undef MBEDTLS_ECP_DP_CURVE448_ENABLED

// UNSURE HERE
#undef MBEDTLS_SHA384_C

// Disable unsupported PSA algorithms to force legacy fallbacks (Infineon PSA limitations)
#if 0
#undef MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN
#undef PSA_WANT_ALG_RSA_PKCS1V15_SIGN
#endif
// PSA ECDH enabled but with reduced buffer sizes to avoid Infineon export bug

#if 0
// EXPLORE THIS?
// Reduce SSL buffer sizes to avoid Infineon PSA export bug while maintaining PSA ECDH acceleration
// ECDH public keys are ~65 bytes, so 2KB is more than sufficient and avoids PSA buffer size bug
#undef MBEDTLS_SSL_IN_CONTENT_LEN
#define MBEDTLS_SSL_IN_CONTENT_LEN 2048

#undef MBEDTLS_SSL_OUT_CONTENT_LEN
#define MBEDTLS_SSL_OUT_CONTENT_LEN 2048

// Reduce DTLS buffering proportionally
#undef MBEDTLS_SSL_DTLS_MAX_BUFFERING
#define MBEDTLS_SSL_DTLS_MAX_BUFFERING 4096

//  Kimi K2 suggestion to deal with ephemeral keys
#endif

#if 0
/* Kimi K2 said:
AWS IoT Core is using ECDH key exchange with RSA signature (ECDHE-RSA cipher suite). The flow is:
✅ Certificate verified (contains RSA public key)
✅ Server sends ECDH parameters (secp256r1 curve, public point)
❌ Server signs those parameters with its RSA private key
❌ Your client tries to import the RSA public key to verify that signature
❌ PSA refuses: PSA_ERROR_NOT_SUPPORTED
*/

#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY        1
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN          1

/* Grok thinks: */
// #undef PSA_WANT_ALG_ECDH  // Actually, Infineon PSA DOES support ECDH!
#undef MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN
#undef PSA_WANT_ALG_RSA_PKCS1V15_SIGN
#endif

#undef MBEDTLS_SSL_PROTO_TLS1_3


// Force ECC-only cipher suites to avoid RSA operations entirely
// Enable ECC-based key exchanges
// #define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED  // Disabled due to PSA export issues
#define MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED     // Try static ECDH first

// Disable all RSA-based key exchanges to force ECC
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED

// Enable ECDSA support
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECDSA_DETERMINISTIC_ENABLED

// Enable ECC cryptography
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED

// Ensure we have the necessary cipher suites for ECC
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_GCM

// We want more prints

#define MBEDTLS_DEBUG_C


/*
 * Appended (non-intrusive) TLS fragment sizing
 * - Keep original overlay content intact; just clamp TLS content length here.
 * - Enable the Max Fragment Length extension build-time support.
 * Note: Advertising MFL still depends on runtime calling mbedtls_ssl_conf_max_frag_len().
 */
#ifndef MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
#endif

#undef MBEDTLS_SSL_IN_CONTENT_LEN
#define MBEDTLS_SSL_IN_CONTENT_LEN 2048

#undef MBEDTLS_SSL_OUT_CONTENT_LEN
#define MBEDTLS_SSL_OUT_CONTENT_LEN 2048

#endif /* MBEDTLS_USER_OVERLAY_HEADER */