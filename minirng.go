package minirng

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	gonanoid "github.com/matoous/go-nanoid/v2"
)

var (
	alphaLower  string = "abcdefghijklmnopqrstuvwxyz"
	alphaUpper  string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	number      string = "1234567890"
	alphaNumber        = alphaLower + alphaUpper + number
)

// rngByte generates a random byte array using the given seed and content.
func rngByte(s, c []byte) []byte {
	h := hmac.New(sha256.New, s)
	h.Write(c)
	return h.Sum(nil)
}

// rngString generates a random string using the given seed and content.
func rngString(s, c []byte) string {
	d := rngByte(s, c)
	return hex.EncodeToString(d)
}

// GenNanoID generates a random string using the given size.
func GenNanoID(size int) string {
	if size <= 0 {
		size = 10
	}
	s, e := gonanoid.Generate(alphaNumber, size)
	if e != nil {
		return ""
	}
	return s
}

type MiniRNG struct {
	hash []byte
}

func NewMiniRNG(hash []byte) *MiniRNG {
	return &MiniRNG{hash: hash}
}

// SeedToHash generates a random string using the given seed and content.
func (c *MiniRNG) SeedToHash(seed string) string {
	return rngString([]byte(seed), c.hash)
}

// Digest generates a random byte array using the given server seed, client seed, nonce, and number.
func (c *MiniRNG) Digest(serverSeed, clientSeed string, nonce, num int) []byte {
	str := fmt.Sprintf("%s:%d:%d", clientSeed, nonce, num)
	return rngByte([]byte(serverSeed), []byte(str))
}
