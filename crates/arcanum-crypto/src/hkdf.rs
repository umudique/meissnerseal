// SPDX-License-Identifier: Apache-2.0
// HKDF domain separation registry v1
// root_prk = HKDF-Extract(salt = H("arcanum-root-salt-v1" || vault_id || header_nonce), ikm = vault_root_key)
