package utils

import (
	"io"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"crypto/x509"
	"crypto/rsa"
	"math"
)

import (
	"crypto/rand"
	"net"
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

// 加密
func RsaEncrypt(origData []byte, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey) //将密钥解析成公钥实例
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes) //解析pem.Decode（）返回的Block指针实例
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData) //RSA算法加密
}

// 解密
func RsaDecrypt(ciphertext []byte, privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey) //将密钥解析成私钥实例
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes) //解析pem.Decode（）返回的Block指针实例
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv.(*rsa.PrivateKey), ciphertext) //RSA算法解密
}

// 四舍五入
func Round(val float64, places int) float64 {
	var t float64
	f := math.Pow10(places)
	x := val * f
	if math.IsInf(x, 0) || math.IsNaN(x) {
		return val
	}
	if x >= 0.0 {
		t = math.Ceil(x)
		if (t - x) > 0.50000000001 {
			t -= 1.0
		}
	} else {
		t = math.Ceil(-x)
		if (t + x) > 0.50000000001 {
			t -= 1.0
		}
		t = -t
	}
	x = t / f

	if !math.IsInf(x, 0) {
		return x
	}

	return t
}

// 本机ip地址
func LocalAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		var ip string
		for _, address := range addrs {
			// 检查ip地址判断是否回环地址
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ip += ipnet.IP.To4().String() + ","
				}
			}
		}
		ip = strings.TrimRight(ip, ",")
		return ip
	}
	return "127.0.0.1"
}