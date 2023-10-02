package cryptohelper

import (
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"testing"
)

func TestClientProof(t *testing.T) {
	clientProofExpect := "ac0a328baf7a34985b94541214c56eb0306d1c978a06c68dba8b13cde0c3b85c"
	password := "testPassword123"
	salt, err := hex.DecodeString("a058795da8a71336271577598a10bd4267e51b36f70594e824640bf7a37b17f9")
	if err != nil {
		fmt.Printf("could not decode string: %s\n", err)
		os.Exit(1)
	}

	iterations := 1000
	authMessage := "a825e633d7d46b10dc8a0c9b41bc3173f64187789425e7ff2ecce95232021d69,a825e633d7d46b10dc8a0c9b41bc3173f64187789425e7ff2ecce95232021d69IB07VhGRTZ0h6uY4RDjl0vCZNIJqc2CZ,a825e633d7d46b10dc8a0c9b41bc3173f64187789425e7ff2ecce95232021d69IB07VhGRTZ0h6uY4RDjl0vCZNIJqc2CZ"
	want := regexp.MustCompile(clientProofExpect)
	msg := ClientProof(password, salt, iterations, authMessage)
	if !want.MatchString(msg) {
		t.Fatalf(`ClientProof() = %q, want match for %#q`, msg, want)
	}
}

func TestSaltedPassword(t *testing.T) {
	saltedPasswordExpect := "70e9a1b9826d318d1b81a6089acee2da55e338f4ac8ed5ee2769ca56a4ca7725"
	password := "testPassword123"
	salt, err := hex.DecodeString("a058795da8a71336271577598a10bd4267e51b36f70594e824640bf7a37b17f9")
	if err != nil {
		fmt.Printf("could not decode string: %s\n", err)
		os.Exit(1)
	}
	iterations := 1000
	want := regexp.MustCompile(saltedPasswordExpect)
	msg := SaltedPassword(password, salt, iterations)
	if !want.MatchString(hex.EncodeToString(msg)) {
		t.Fatalf(`SaltedPassword() = %q, want match for %#q`, hex.EncodeToString(msg), want)
	}
}

func TestClientKey(t *testing.T) {
	clientKeyExpect := "173828e5fa7ea0424a1325cb429c23dfb4ec9112ccb9bc431705183a648fe453"
	saltedPassword := "a82316a6f342ccff7afb5906b476589c9f1f0badda14501eb50c2c8ceed7d982"

	decSaltedPass, err := hex.DecodeString(saltedPassword)
	if err != nil {
		fmt.Printf("could not decode string: %s\n", err)
		os.Exit(1)
	}

	want := regexp.MustCompile(clientKeyExpect)
	msg := ClientKey(decSaltedPass)
	if !want.MatchString(hex.EncodeToString(msg)) {
		t.Fatalf(`ClientKey() = %q, want match for %#q`, hex.EncodeToString(msg), want)
	}
}

func TestStoredKey(t *testing.T) {
	storedKeyExpect := "074dc84629c0fa535ac13b46233dbb0de95d4d3102612caac251da714226f691"
	clientKey := "173828e5fa7ea0424a1325cb429c23dfb4ec9112ccb9bc431705183a648fe453"

	decClientKey, err := hex.DecodeString(clientKey)
	if err != nil {
		fmt.Printf("could not decode string: %s\n", err)
		os.Exit(1)
	}

	want := regexp.MustCompile(storedKeyExpect)
	msg := StoredKey(decClientKey)
	if !want.MatchString(hex.EncodeToString(msg)) {
		t.Fatalf(`StoredKey() = %q, want match for %#q`, hex.EncodeToString(msg), want)
	}
}

func TestSigniture(t *testing.T) {
	signitureExpect := "f185ad8e8033cd4b0189fe4d2b464b1bbf1972995954e61ee4dbd849d248f48e"
	storedKey := "074dc84629c0fa535ac13b46233dbb0de95d4d3102612caac251da714226f691"
	authMessage := "a825e633d7d46b10dc8a0c9b41bc3173f64187789425e7ff2ecce95232021d69,a825e633d7d46b10dc8a0c9b41bc3173f64187789425e7ff2ecce95232021d69IB07VhGRTZ0h6uY4RDjl0vCZNIJqc2CZ,a825e633d7d46b10dc8a0c9b41bc3173f64187789425e7ff2ecce95232021d69IB07VhGRTZ0h6uY4RDjl0vCZNIJqc2CZ"

	decStoredKey, err := hex.DecodeString(storedKey)
	if err != nil {
		fmt.Printf("could not decode string: %s\n", err)
		os.Exit(1)
	}

	want := regexp.MustCompile(signitureExpect)
	msg := Signature(decStoredKey, authMessage)
	if !want.MatchString(hex.EncodeToString(msg)) {
		t.Fatalf(`Signature() = %q, want match for %#q`, hex.EncodeToString(msg), want)
	}
}
