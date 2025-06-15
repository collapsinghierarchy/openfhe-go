//go:build openfhe && cgo

package openfhe-go

/*
#cgo CFLAGS:   -I/usr/local/include -I/usr/local/include/openfhe/core -I/usr/local/include/openfhe/pke -I/usr/local/include/openfhe/ -I/usr/local/include/openfhe/binfhe
#cgo CXXFLAGS: -I/usr/local/include -I/usr/local/include/openfhe/core -I/usr/local/include/openfhe/pke -I/usr/local/include/openfhe/ -I/usr/local/include/openfhe/binfhe -std=c++17
#cgo LDFLAGS:  -lOPENFHEcore -lOPENFHEpke -lstdc++ -lm -lpthread
#include "openfhe_c.h"          // header only – no .cpp here
*/
import "C"
import (
	"errors"
	"unsafe"
)

// Context wraps a BGVRNS CryptoContext
type Context struct{ ptr unsafe.Pointer }

// NewBGVRNS creates a new BGVRNS context
func NewBGVRNS(depth uint32, t uint64) *Context {
	return &Context{C.go_bgvrns_new(C.uint(depth), C.uint64_t(t))}
}

// Free releases the underlying C++ CryptoContext
func (c *Context) Free() {
	if c != nil && c.ptr != nil {
		C.go_bgvrns_free(c.ptr)
		c.ptr = nil
	}
}

// Raw returns the underlying pointer for internal use
func (c *Context) Raw() unsafe.Pointer {
	if c == nil {
		return nil
	}
	return c.ptr
}

// PublicKey wraps an opaque PublicKey<DCRTPoly>*
type PublicKey struct{ ptr unsafe.Pointer }

// Raw returns the underlying pointer
func (pk *PublicKey) Raw() unsafe.Pointer {
	if pk == nil {
		return nil
	}
	return pk.ptr
}

// Free releases the C++ PublicKey
func (pk *PublicKey) Free() {
	if pk != nil && pk.ptr != nil {
		C.go_pk_free(pk.ptr)
		pk.ptr = nil
	}
}

// Serialize returns the binary serialization of the public key
func (pk *PublicKey) Serialize() ([]byte, error) {
	if pk == nil || pk.ptr == nil {
		return nil, errors.New("PublicKey is nil")
	}
	var buf *C.uint8_t
	var length C.size_t
	C.go_pk_serialize(pk.ptr, &buf, &length)
	defer C.go_buf_free(buf)
	return C.GoBytes(unsafe.Pointer(buf), C.int(length)), nil
}

// DeserializePublicKey creates a PublicKey from serialized data
func DeserializePublicKey(ctx *Context, data []byte) *PublicKey {
	ptr := C.go_pk_deserialize(ctx.ptr,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)))
	return &PublicKey{ptr}
}

// SecretKey wraps an opaque PrivateKey<DCRTPoly>*
type SecretKey struct{ ptr unsafe.Pointer }

// Raw returns the underlying pointer
func (sk *SecretKey) Raw() unsafe.Pointer {
	if sk == nil {
		return nil
	}
	return sk.ptr
}

// Free releases the C++ SecretKey
func (sk *SecretKey) Free() {
	if sk != nil && sk.ptr != nil {
		C.go_sk_free(sk.ptr)
		sk.ptr = nil
	}
}

// Serialize returns binary serialization of the secret key
func (sk *SecretKey) Serialize() ([]byte, error) {
	if sk == nil || sk.ptr == nil {
		return nil, errors.New("SecretKey is nil")
	}
	var buf *C.uint8_t
	var length C.size_t
	C.go_sk_serialize(sk.ptr, &buf, &length)
	defer C.go_buf_free(buf)
	return C.GoBytes(unsafe.Pointer(buf), C.int(length)), nil
}

// DeserializeSecretKey creates a SecretKey from serialized data
func DeserializeSecretKey(ctx *Context, data []byte) *SecretKey {
	ptr := C.go_sk_deserialize(ctx.ptr,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)))
	return &SecretKey{ptr}
}

// Ciphertext wraps an opaque Ciphertext<DCRTPoly>*
type Ciphertext struct{ ptr unsafe.Pointer }

// Raw returns the underlying pointer
func (ct *Ciphertext) Raw() unsafe.Pointer {
	if ct == nil {
		return nil
	}
	return ct.ptr
}

// Free releases the C++ Ciphertext
func (ct *Ciphertext) Free() {
	if ct != nil && ct.ptr != nil {
		C.go_ct_free(ct.ptr)
		ct.ptr = nil
	}
}

// Serialize returns binary serialization of the ciphertext
func (ct *Ciphertext) Serialize() ([]byte, error) {
	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Ciphertext is nil")
	}
	var buf *C.uint8_t
	var length C.size_t
	C.go_ct_ser(ct.ptr, &buf, &length)
	defer C.go_buf_free(buf)
	return C.GoBytes(unsafe.Pointer(buf), C.int(length)), nil
}

// DeserializeCiphertext creates a Ciphertext from serialized data
func DeserializeCiphertext(ctx *Context, data []byte) *Ciphertext {
	ptr := C.go_ct_deser(ctx.ptr,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)))
	return &Ciphertext{ptr}
}

// KeyGenPtr generates a new key pair, returning opaque pointers
func (c *Context) KeyGenPtr() (*PublicKey, *SecretKey, error) {
	var pkPtr, skPtr unsafe.Pointer
	C.go_keygen_ptr(c.ptr, &pkPtr, &skPtr)
	if pkPtr == nil || skPtr == nil {
		return nil, nil, errors.New("keygen failed")
	}
	return &PublicKey{pkPtr}, &SecretKey{skPtr}, nil
}

// EncryptU64ToPtr encrypts a uint64 to an opaque Ciphertext pointer
func (c *Context) EncryptU64ToPtr(pk *PublicKey, value uint64) (*Ciphertext, error) {
	if pk == nil || pk.ptr == nil {
		return nil, errors.New("PublicKey is nil")
	}
	ptr := C.go_encrypt_u64_ptr_out(c.ptr, pk.ptr, C.uint64_t(value))
	if ptr == nil {
		return nil, errors.New("encryption failed")
	}
	return &Ciphertext{ptr}, nil
}

// DecryptU64FromPtr decrypts an opaque Ciphertext using a SecretKey pointer
func (c *Context) DecryptU64FromPtr(sk *SecretKey, ct *Ciphertext) (uint64, error) {
	if sk == nil || sk.ptr == nil {
		return 0, errors.New("SecretKey is nil")
	}
	if ct == nil || ct.ptr == nil {
		return 0, errors.New("Ciphertext is nil")
	}
	result := C.go_decrypt_u64_ptr(c.ptr, sk.ptr, ct.ptr)
	return uint64(result), nil
}

// EvalAdd homomorphically adds `other` into `acc` (acc = acc + other)
func (c *Context) EvalAdd(acc, other *Ciphertext) error {
	if c == nil || c.ptr == nil {
		return errors.New("Context is nil")
	}
	if acc == nil || acc.ptr == nil {
		return errors.New("acc Ciphertext is nil")
	}
	if other == nil || other.ptr == nil {
		return errors.New("other Ciphertext is nil")
	}
	C.go_eval_add_inplace(c.ptr, acc.ptr, other.ptr)
	return nil
}
