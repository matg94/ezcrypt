package ezcrypt

import "testing"

func TestReadPrivateKey() {}

func TestReadPublicKey() {}

func TestDecodePrivateKey() {}

func TestDecodePublicKey() {}

func TestEncodePrivateKey() {}

func TestEncodePublicKey() {}

func TestGeneratePrivateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Logf("expected err to be <nil> but got %v", err)
		t.Fail()
	}
}

func TestGeneratePublicKey() {}

func TestWritePrivateKey() {}

func TestWritePublicKey() {}
