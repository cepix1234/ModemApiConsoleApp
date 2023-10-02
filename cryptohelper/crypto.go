package cryptohelper

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

func Nonce() string {
	nonceBytes := make([]byte, 32)
	rand.Read(nonceBytes)
	// hexChars := []byte{}
	// for index := range nonceBytes {
	// 	bite := byte((uint(nonceBytes[int(uint(index)>>2)]) >> (24 - (index%4)*8)) & 0xff)
	// 	hexChars = append(hexChars, byte(uint(bite)>>4))
	// 	hexChars = append(hexChars, bite&0xff)
	// }
	return hex.EncodeToString(nonceBytes)
}

func SaltedPassword(password string, salt []byte, iterations int) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
}

func ClientKey(saltPwd []byte) []byte {
	h := hmac.New(sha256.New, []byte("Client Key"))
	h.Write(saltPwd)
	return h.Sum(nil)
}

func StoredKey(clientKey []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(clientKey)
	return h.Sum(nil)
}

func Signature(storedKey []byte, authMessage string) []byte {
	h := hmac.New(sha256.New, []byte(authMessage))
	io.WriteString(h, string(storedKey))
	return h.Sum(nil)
}

func ClientProof(password string, salt []byte, iterations int, authMessage string) string {
	var spwd = SaltedPassword(password, salt, iterations)
	var ckey = ClientKey(spwd)
	var skey = StoredKey(ckey)
	var csig = Signature(skey, authMessage)

	for i := 0; i < len(ckey); i++ {
		ckey[i] = ckey[i] ^ csig[i]
	}
	return hex.EncodeToString(ckey)
}
