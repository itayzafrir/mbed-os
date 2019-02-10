/*
 * Copyright (c) 2019, Arm Limited and affiliates
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PSA_CRYPTO_ACCESS_CONTROL_H
#define PSA_CRYPTO_ACCESS_CONTROL_H

#include <stdint.h>

#include "psa_crypto_core.h"
#include "crypto_platform.h"
#include "mbed_assert.h"

void psa_crypto_access_control_init(void);

void psa_crypto_access_control_destroy(void);

void psa_crypto_access_control_register_handle(psa_key_handle_t key_handle, int32_t partition_id);

void psa_crypto_access_control_unregister_handle(psa_key_handle_t key_handle);

uint8_t psa_crypto_access_control_is_handle_permitted(psa_key_handle_t key_handle, int32_t partition_id);

static inline void psa_crypto_access_control_assemble_psa_key_id(psa_key_id_t *id, int32_t partition_id)
{
    MBED_STATIC_ASSERT(sizeof(psa_key_id_t) == 8, "Unexpected psa_key_id_t size");

    /* move the 32 bit client representation of psa_key_id_t to the upper 32 bits of the 64 bit
     * server representation of psa_key_id_t. */
    *id <<= 32;
    /* the lower 32 bits of the 64 bit server representation of psa_key_id_t represent
     * the calling partition id. */
    *id |= (uint32_t)partition_id;
}

#endif /* PSA_CRYPTO_ACCESS_CONTROL_H */
