#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ────────── Context ──────────────────────────────────────────────────────
void*    go_bgvrns_new(uint32_t multiplicative_depth, uint64_t t);
void     go_bgvrns_free(void* ctx);

// ────────── Key Generation ──────────────────────────────────────────────
void     go_keygen_ptr(void* ctx, void** pk_ptr, void** sk_ptr);

// ────────── PublicKey ───────────────────────────────────────────────────
void     go_pk_serialize(void* pk, uint8_t** buf, size_t* len);
void*    go_pk_deserialize(void* ctx, const uint8_t* buf, size_t len);
void     go_pk_free(void* pk);

// ────────── SecretKey ───────────────────────────────────────────────────
void     go_sk_serialize(void* sk, uint8_t** buf, size_t* len);
void*    go_sk_deserialize(void* ctx, const uint8_t* buf, size_t len);
void     go_sk_free(void* sk);

// ────────── Ciphertext ──────────────────────────────────────────────────
void*    go_encrypt_u64_ptr_out(void* ctx, void* pk_ptr, uint64_t value);
uint64_t go_decrypt_u64_ptr(void* ctx, void* sk_ptr, void* ct_ptr);
void     go_ct_ser(void* ct, uint8_t** buf, size_t* len);
void*    go_ct_deser(void* ctx, const uint8_t* buf, size_t len);
void     go_ct_free(void* ct);

// ────────── Evaluation ──────────────────────────────────────────────────
void     go_eval_add_inplace(void* ctx, void* acc_ptr, void* other_ptr);

// ────────── Misc ───────────────────────────────────────────────────────
void     go_buf_free(uint8_t* p);

#ifdef __cplusplus
}
#endif
