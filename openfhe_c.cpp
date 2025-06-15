//go:build openfhe && cgo
#include "openfhe_c.h"

#include <openfhe/core/openfhecore.h>   // v1.3 header root
#include <openfhe/pke/openfhe.h>
#include <openfhe/core/utils/serial.h> 
#include <openfhe/pke/ciphertext-ser.h>
#include <openfhe/pke/key/key-ser.h>
#include <openfhe/pke/scheme/bgvrns/bgvrns-ser.h>

using namespace lbcrypto;

// ────────── Serialization Helpers ───────────────────────────────────────
#include <vector>
#include <sstream>
#include <cstring>
#include <cstdlib>

template <typename T>
bool serialize_to_vec(const T& obj, std::vector<uint8_t>& out) {
    try {
        std::stringstream ss;
        Serial::Serialize(obj, ss, SerType::BINARY);
        auto s = ss.str();
        out.assign(s.begin(), s.end());
        return true;
    } catch (...) {
        out.clear();
        return false;
    }
}

template <typename T>
bool deserialize_from_buf(T& obj, const uint8_t* buf, size_t len) {
    std::stringstream ss;
    ss.write(reinterpret_cast<const char*>(buf), len);
    ss.seekg(0);
    try {
        Serial::Deserialize(obj, ss, SerType::BINARY);
        return true;
    } catch (...) {
        return false;
    }
}

// ────────── Context ────────────────────────────────────────────────────
void* go_bgvrns_new(uint32_t depth, uint64_t t) {
    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(depth);
    params.SetPlaintextModulus(t);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    return new CryptoContext<DCRTPoly>(cc);
}

void go_bgvrns_free(void* ctx) {
    delete static_cast<CryptoContext<DCRTPoly>*>(ctx);
}

// ────────── Key Generation ──────────────────────────────────────────────
void go_keygen_ptr(void* ctx, void** pk_ptr, void** sk_ptr) {
    auto cc = *static_cast<CryptoContext<DCRTPoly>*>(ctx);
    auto kp = cc->KeyGen();
    *pk_ptr = new PublicKey<DCRTPoly>(kp.publicKey);
    *sk_ptr = new PrivateKey<DCRTPoly>(kp.secretKey);
}

// ────────── PublicKey ───────────────────────────────────────────────────
void go_pk_serialize(void* pk_ptr, uint8_t** buf, size_t* len) {
    auto& pk = *static_cast<PublicKey<DCRTPoly>*>(pk_ptr);
    std::vector<uint8_t> tmp;
    if (!serialize_to_vec(pk, tmp)) {
        *buf = nullptr;
        *len = 0;
        return;
    }
    *len = tmp.size();
    *buf = static_cast<uint8_t*>(malloc(*len));
    memcpy(*buf, tmp.data(), *len);
}

void* go_pk_deserialize(void* ctx, const uint8_t* buf, size_t len) {
    auto pk = new PublicKey<DCRTPoly>();
    if (!deserialize_from_buf(*pk, buf, len)) {
        delete pk;
        return nullptr;
    }
    return pk;
}

void go_pk_free(void* pk_ptr) {
    delete static_cast<PublicKey<DCRTPoly>*>(pk_ptr);
}

// ────────── SecretKey ───────────────────────────────────────────────────
void go_sk_serialize(void* sk_ptr, uint8_t** buf, size_t* len) {
    auto& sk = *static_cast<PrivateKey<DCRTPoly>*>(sk_ptr);
    std::vector<uint8_t> tmp;
    if (!serialize_to_vec(sk, tmp)) {
        *buf = nullptr;
        *len = 0;
        return;
    }
    *len = tmp.size();
    *buf = static_cast<uint8_t*>(malloc(*len));
    memcpy(*buf, tmp.data(), *len);
}

void* go_sk_deserialize(void* ctx, const uint8_t* buf, size_t len) {
    auto sk = new PrivateKey<DCRTPoly>();
    if (!deserialize_from_buf(*sk, buf, len)) {
        delete sk;
        return nullptr;
    }
    return sk;
}

void go_sk_free(void* sk_ptr) {
    delete static_cast<PrivateKey<DCRTPoly>*>(sk_ptr);
}

// ────────── Encryption/Decryption ──────────────────────────────────────
void* go_encrypt_u64_ptr_out(void* ctx, void* pk_ptr, uint64_t value) {
    auto cc = *static_cast<CryptoContext<DCRTPoly>*>(ctx);
    auto& pk = *static_cast<PublicKey<DCRTPoly>*>(pk_ptr);
    Plaintext pt = cc->MakePackedPlaintext({static_cast<int64_t>(value)});
    auto ct = cc->Encrypt(pk, pt);
    return new Ciphertext<DCRTPoly>(ct);
}

uint64_t go_decrypt_u64_ptr(void* ctx, void* sk_ptr, void* ct_ptr) {
    if (!ctx || !sk_ptr || !ct_ptr) return 0;
    auto cc = *static_cast<CryptoContext<DCRTPoly>*>(ctx);
    auto& sk = *static_cast<PrivateKey<DCRTPoly>*>(sk_ptr);
    auto& ct = *static_cast<Ciphertext<DCRTPoly>*>(ct_ptr);
    Plaintext pt;
    cc->Decrypt(sk, ct, &pt);
    pt->SetLength(1);
    return static_cast<uint64_t>(pt->GetPackedValue()[0]);
}

// ────────── Ciphertext Serialization ───────────────────────────────────
void go_ct_ser(void* ct_ptr, uint8_t** buf, size_t* len) {
    auto& ct = *static_cast<Ciphertext<DCRTPoly>*>(ct_ptr);
    std::vector<uint8_t> tmp;
    if (!serialize_to_vec(ct, tmp)) {
        *buf = nullptr;
        *len = 0;
        return;
    }
    *len = tmp.size();
    *buf = static_cast<uint8_t*>(malloc(*len));
    memcpy(*buf, tmp.data(), *len);
}

void* go_ct_deser(void* ctx, const uint8_t* buf, size_t len) {
    auto ct = new Ciphertext<DCRTPoly>();
    if (!deserialize_from_buf(*ct, buf, len)) {
        delete ct;
        return nullptr;
    }
    return ct;
}

void go_ct_free(void* ct_ptr) {
    delete static_cast<Ciphertext<DCRTPoly>*>(ct_ptr);
}

// ────────── Evaluation ─────────────────────────────────────────────────
void go_eval_add_inplace(void* ctx, void* acc_ptr, void* other_ptr) {
    auto cc = *static_cast<CryptoContext<DCRTPoly>*>(ctx);
    auto& acc   = *static_cast<Ciphertext<DCRTPoly>*>(acc_ptr);
    auto& other = *static_cast<Ciphertext<DCRTPoly>*>(other_ptr);
    acc = cc->EvalAdd(acc, other);
}

// ────────── Misc ───────────────────────────────────────────────────────
void go_buf_free(uint8_t* p) {
    free(p);
}
