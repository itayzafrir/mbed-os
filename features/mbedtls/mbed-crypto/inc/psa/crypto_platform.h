/**
 * \file psa/crypto_platform.h
 *
 * \brief PSA cryptography module: Mbed TLS platfom definitions
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * This file contains platform-dependent type definitions.
 *
 * In implementations with isolation between the application and the
 * cryptography module, implementers should take care to ensure that
 * the definitions that are exposed to applications match what the
 * module implements.
 */
/*
 *  Copyright (C) 2018, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef PSA_CRYPTO_PLATFORM_H
#define PSA_CRYPTO_PLATFORM_H

/* Include the Mbed TLS configuration file, the way Mbed TLS does it
 * in each of its header files. */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "../mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/* PSA requires several types which C99 provides in stdint.h. */
#include <stdint.h>

/* Integral type representing a key handle. */
typedef uint16_t psa_key_handle_t;

/* Applications always see 32-bit key ids. */
typedef uint32_t psa_app_key_id_t;

#if defined(MBEDTLS_PSA_CRYPTO_SPM)
/* When the library is built as part of a PSA Cryptography service on a
 * PSA platform, a key file ID encodes both the 32-bit key ID used by the
 * application and the signed 32-bit partition ID of the key owner. */
typedef struct
{
    int32_t owner;
    uint32_t key_id;
} psa_key_file_id_t;
typedef psa_key_file_id_t psa_key_id_t;
#define PSA_KEY_FILE_GET_KEY_ID( file_id ) ( ( file_id ).key_id )
#else
typedef uint32_t psa_key_file_id_t;
#define PSA_KEY_FILE_GET_KEY_ID( key_id ) ( key_id )
#endif

#endif /* PSA_CRYPTO_PLATFORM_H */
