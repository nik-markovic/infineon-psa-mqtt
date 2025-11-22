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

// needed for TLS v1.3:
#define PSA_WANT_ALG_HKDF_EXTRACT               1
#define PSA_WANT_ALG_HKDF_EXPAND                1
// or:
// #undef MBEDTLS_SSL_PROTO_TLS1_3


#define MBEDTLS_SSL_PROTO_TLS1_3
// #define MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
#define MBEDTLS_HKDF_C
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED

// Ensure ECDSA is supported along with our key SECP256R1 curve
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECDSA_DETERMINISTIC_ENABLED
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED


// Force ECC-only cipher suites to avoid RSA operations entirely
// Enable ECC-based key exchanges
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED

// Ensure we have the necessary cipher suites for ECC
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_GCM


// Disable all RSA-based key exchanges to force ECC TLS negotiation
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED

#undef MBEDTLS_SSL_IN_CONTENT_LEN
#define MBEDTLS_SSL_IN_CONTENT_LEN 4096

#undef MBEDTLS_SSL_OUT_CONTENT_LEN
#define MBEDTLS_SSL_OUT_CONTENT_LEN 4096

// We want more prints
// #define MBEDTLS_DEBUG_C

//////////////////////////////////////
#endif // MBEDTLS_USER_OVERLAY_HEADER
