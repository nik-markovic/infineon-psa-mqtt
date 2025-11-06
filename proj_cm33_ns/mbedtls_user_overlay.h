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

// Enable ALT signing to override ECDSA sign with PSA call
// #define MBEDTLS_ECDSA_SIGN_ALT  // Removed to avoid library conflicts; use existing opaque PSA flow instead

#endif /* MBEDTLS_USER_OVERLAY_HEADER */