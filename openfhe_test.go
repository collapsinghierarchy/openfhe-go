//go:build openfhe && cgo

package main

import "testing"

const (
	testDepth = 2
	testT     = 65537
	testMsg   = uint64(42)
)

func TestContextLifecycle(t *testing.T) {
	ctx := NewBGVRNS(testDepth, testT)
	if ctx == nil || ctx.Raw() == nil {
		t.Fatal("Failed to create Context")
	}
	ctx.Free()
}

func TestKeyGenAndSerialize(t *testing.T) {
	ctx := NewBGVRNS(testDepth, testT)
	defer ctx.Free()

	pk, sk, err := ctx.KeyGenPtr()
	if err != nil {
		t.Fatalf("KeyGenPtr failed: %v", err)
	}
	defer pk.Free()
	defer sk.Free()

	pkBytes, err := pk.Serialize()
	if err != nil || len(pkBytes) == 0 {
		t.Fatalf("PublicKey.Serialize failed: %v", err)
	}
	skBytes, err := sk.Serialize()
	if err != nil || len(skBytes) == 0 {
		t.Fatalf("SecretKey.Serialize failed: %v", err)
	}

	pk2 := DeserializePublicKey(ctx, pkBytes)
	if pk2 == nil || pk2.Raw() == nil {
		t.Fatal("DeserializePublicKey failed")
	}
	defer pk2.Free()

	sk2 := DeserializeSecretKey(ctx, skBytes)
	if sk2 == nil || sk2.Raw() == nil {
		t.Fatal("DeserializeSecretKey failed")
	}
	defer sk2.Free()
}

func TestEncryptDecryptWithPtrs(t *testing.T) {
	ctx := NewBGVRNS(testDepth, testT)
	defer ctx.Free()

	pk, sk, err := ctx.KeyGenPtr()
	if err != nil {
		t.Fatalf("KeyGenPtr failed: %v", err)
	}
	defer pk.Free()
	defer sk.Free()

	ct, err := ctx.EncryptU64ToPtr(pk, testMsg)
	if err != nil {
		t.Fatalf("EncryptU64ToPtr failed: %v", err)
	}
	defer ct.Free()

	plain, err := ctx.DecryptU64FromPtr(sk, ct)
	if err != nil {
		t.Fatalf("DecryptU64FromPtr failed: %v", err)
	}
	if plain != testMsg {
		t.Fatalf("Decryption mismatch: got %d, want %d", plain, testMsg)
	}
}

func TestCiphertextSerialize(t *testing.T) {
	ctx := NewBGVRNS(testDepth, testT)
	defer ctx.Free()

	pk, sk, err := ctx.KeyGenPtr()
	if err != nil {
		t.Fatalf("KeyGenPtr failed: %v", err)
	}
	defer pk.Free()
	defer sk.Free()

	ct, err := ctx.EncryptU64ToPtr(pk, testMsg)
	if err != nil {
		t.Fatalf("EncryptU64ToPtr failed: %v", err)
	}
	defer ct.Free()

	ctBytes, err := ct.Serialize()
	if err != nil || len(ctBytes) == 0 {
		t.Fatalf("Ciphertext.Serialize failed: %v", err)
	}

	ct2 := DeserializeCiphertext(ctx, ctBytes)
	if ct2 == nil || ct2.Raw() == nil {
		t.Fatal("DeserializeCiphertext failed")
	}
	defer ct2.Free()

	plain, err := ctx.DecryptU64FromPtr(sk, ct2)
	if err != nil {
		t.Fatalf("DecryptU64FromPtr failed after deserialize: %v", err)
	}
	if plain != testMsg {
		t.Fatalf("Post-serialize decrypt mismatch: got %d, want %d", plain, testMsg)
	}
}

func TestEvalAdd(t *testing.T) {
	ctx := NewBGVRNS(testDepth, testT)
	defer ctx.Free()

	pk, sk, err := ctx.KeyGenPtr()
	if err != nil {
		t.Fatalf("KeyGenPtr failed: %v", err)
	}
	defer pk.Free()
	defer sk.Free()

	ct1, err := ctx.EncryptU64ToPtr(pk, 10)
	if err != nil {
		t.Fatalf("EncryptU64ToPtr failed: %v", err)
	}
	defer ct1.Free()

	ct2, err := ctx.EncryptU64ToPtr(pk, 32)
	if err != nil {
		t.Fatalf("EncryptU64ToPtr failed: %v", err)
	}
	defer ct2.Free()

	if err := ctx.EvalAdd(ct1, ct2); err != nil {
		t.Fatalf("EvalAdd failed: %v", err)
	}

	sum, err := ctx.DecryptU64FromPtr(sk, ct1)
	if err != nil {
		t.Fatalf("DecryptU64FromPtr failed: %v", err)
	}
	if sum != 42 {
		t.Fatalf("EvalAdd result mismatch: got %d, want 42", sum)
	}
}
