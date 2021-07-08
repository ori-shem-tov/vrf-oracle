package tealtools

import (
	"crypto/sha512"
	"encoding/base64"
)

func CutTeal(program []byte, prefixEnd, suffixStart int) (string, string, string) {
	prefix := program[:prefixEnd]
	suffix := program[suffixStart:]
	prefixB64 := base64.StdEncoding.EncodeToString(prefix)
	suffixB64 := base64.StdEncoding.EncodeToString(suffix)
	suffixHash := sha512.Sum512_256(suffix)
	suffixHashB64 := base64.StdEncoding.EncodeToString(suffixHash[:])
	return prefixB64, suffixB64, suffixHashB64
}
