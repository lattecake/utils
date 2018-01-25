package rand

import (
	"io"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"encoding/hex"
	"crypto/rand"
)

// 生成随机字符串
func RandomString() string {
	b := make([]byte, 64)

	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}

	h := sha256.New()
	h.Write([]byte(base64.URLEncoding.EncodeToString(b)))
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}


