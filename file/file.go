package file

import (
	"os"
	"mime/multipart"
	"crypto/md5"
	"io"
	"encoding/hex"
)

// 判断目录是否存在
func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// md5 file
func Md5File(f multipart.File) (s string, err error) {
	md5hash := md5.New()
	if _, err := io.Copy(md5hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(md5hash.Sum(nil)), nil
}
