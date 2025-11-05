# PSA-based mTLS Implementation for MQTT

## Overview

This implementation provides a minimal, injection-based approach to MQTT mTLS authentication using PSA (Platform Security Architecture) Crypto and TF-M (Trusted Firmware-M) on the Infineon PSoC Edge platform.

**Key Principle:** The private key is never exposed in user-space. Instead, it's stored securely in the secure enclave and PSA Crypto performs signing operations during the TLS handshake.

## Architecture

### Files Modified/Created

1. **`psa_test_new.c`** (NEW)
   - PSA key and certificate setup
   - `psa_mqtt_inject_credentials()` - Single entry point that:
     - Initializes PSA Crypto
     - Generates or retrieves persistent ECC P-256 key
     - Generates self-signed X.509 certificate
     - Injects certificate and key into MQTT client credentials before connection

2. **`mqtt_task.c`** (MODIFIED - 2 lines)
   - Added extern declaration for `psa_mqtt_inject_credentials()` 
   - Added single call to `psa_mqtt_inject_credentials(&security_info)` right before `cy_mqtt_create()`
   - Pattern: `// begin hack:` → `psa_mqtt_inject_credentials(&security_info);` → `// end hack:`

3. **`mbedtls_user_overlay.h`** (ALREADY CONFIGURED)
   - Defines `MBEDTLS_PK_USE_PSA_EC_DATA` - Store EC keys as PSA opaque keys
   - Defines `MBEDTLS_X509_*` - X.509 certificate creation support
   - No additional changes needed

## How It Works

### 1. PSA Key Setup
- On first run: Generates persistent ECC P-256 key (PSA key slot 1)
- On subsequent runs: Reuses existing key (persistent storage)
- Key is stored only in secure memory - never exposed to application

### 2. Certificate Generation
- Generates self-signed X.509 certificate
- Certificate signed using PSA key (signing done in secure context)
- Certificate returned in PEM format for MQTT client

### 3. Credential Injection
- Before MQTT client creation, `psa_mqtt_inject_credentials()` is called
- Updates `security_info` pointer with:
  - `client_cert` → PSA-generated self-signed certificate (PEM)
  - `private_key` → MbedTLS PK context (opaque handle to PSA key)
  - `private_key_size` → Size of PK context

### 4. TLS Handshake
- MbedTLS requests signature from PK context
- MbedTLS calls PSA Crypto via `mbedtls_pk_setup_opaque()`
- PSA signs digest in secure context (via TF-M)
- Signature returned to TLS handshake
- **Private key never materialized in user-space**

## Configuration

### Required Build Defines (Already in Makefile)
```makefile
CY_TFM_PSA_SUPPORTED      # Enable PSA support
TFM_MULTI_CORE_NS_OS      # Enable TF-M multi-core
```

### MbedTLS Configuration
- `MBEDTLS_USE_PSA_CRYPTO` - Already enabled in base config
- `MBEDTLS_PK_USE_PSA_EC_DATA` - Defined in `mbedtls_user_overlay.h`
- X.509 support - Defined in `mbedtls_user_overlay.h`

### cy-mbedtls-acceleration Library
- **No conflicts!** When `CY_TFM_PSA_SUPPORTED` is defined:
  - Library automatically disables ALT functions (MBEDTLS_ECP_ALT, MBEDTLS_ECDSA_SIGN_ALT)
  - This prevents conflicts with PSA implementation
  - Guard in library: `#if !defined(CY_TFM_PSA_SUPPORTED)`

## Testing

The implementation is minimal and focused on the critical path:

1. **PSA Initialization:** `psa_crypto_init()` called automatically on first credential injection
2. **Key Persistence:** Existing key is reused if already created
3. **Certificate Generation:** Self-signed cert created each run (can be cached if needed)
4. **Credential Injection:** Happens silently before MQTT client creation

To test:
1. Build the project: `make build_proj` (proj_cm33_ns)
2. Program to device: `make program_proj`
3. Observe MQTT connection with PSA-based authentication (no user-space private key exposure)

## Code Injection Pattern

This implementation follows the minimal injection pattern suggested:

```c
// In mqtt_task.c (line ~449):

// PSA mTLS: Inject PSA-based credentials before MQTT client creation
psa_mqtt_inject_credentials(&security_info);

// Create the MQTT client instance.
result = cy_mqtt_create(mqtt_network_buffer, MQTT_NETWORK_BUFFER_SIZE,
                        security_info, &broker_info, MQTT_HANDLE_DESCRIPTOR,
                        &mqtt_connection);
```

This pattern:
- ✅ Minimal code changes
- ✅ No header file hacks
- ✅ Extern declaration only
- ✅ Single function call injection
- ✅ Modifies credentials in-place before use

## Security Properties

1. **Private Key Protection:**
   - Key stored only in secure enclave (TF-M secure context)
   - Never materialized in non-secure memory
   - PSA handles only

2. **Certificate Handling:**
   - Self-signed certificate (can be replaced with proper cert)
   - Stored in user-space but non-critical for security

3. **Signing Operations:**
   - All ECDSA signing done in secure context
   - Challenge digest never combined with key in non-secure space

## Limitations & Future Improvements

1. **Current:** Self-signed certificate
   - Future: Load external CA-signed certificate (already generated, just store path)

2. **Current:** Certificate regenerated each run
   - Future: Cache certificate in persistent storage to avoid regeneration overhead

3. **Current:** P-256 only
   - Future: Support additional curves (P-384, etc.)

4. **Current:** No certificate chain validation
   - Future: Add root CA validation if needed for specific deployments

## Compatibility Notes

- **MbedTLS:** v3.0+ (current: ifx-mbedtls release-v3.6.400)
- **PSA Crypto:** Enabled via TF-M
- **CY-mbedtls-acceleration:** v3.0 (auto-compatible with PSA via guard)
- **MQTT Client:** cy-mqtt v4.7.0+ (uses MbedTLS for TLS)
- **TLS Version:** 1.2+ (via MbedTLS)

## Build Status

✅ Builds successfully (no compilation errors)
✅ No linker errors
✅ No conflicts with cy-mbedtls-acceleration
✅ PSA configuration correct
