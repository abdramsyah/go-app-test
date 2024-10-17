package util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"io"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func Encrypt(data []byte, passphrase string) (encryptedText string, err error) {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(crand.Reader, nonce); err != nil {
		return
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	encryptedText = base64.StdEncoding.EncodeToString(ciphertext)
	return
}

func Decrypt(data string, passphrase string) (decryptedData string, err error) {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	decodedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := decodedData[:nonceSize], decodedData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return
	}

	decryptedData = string(plaintext)
	return
}

//https://play.golang.org/p/pETZuK6fwB2

func AESEncrypt(src string, key string, initialVector string) (crypted []byte, err error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return
	}
	if src == "" {
		err = errors.New("Plain content empty")
		return
	}
	ecb := cipher.NewCBCEncrypter(block, []byte(initialVector))
	content := []byte(src)
	content = PKCS5Padding(content, block.BlockSize())
	crypted = make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)

	return
}

func AESDecrypt(crypt []byte, key string, initialVector string) (decrypted []byte, err error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return
	}
	if len(crypt) == 0 {
		err = errors.New("Plain content empty")
		return
	}
	ecb := cipher.NewCBCDecrypter(block, []byte(initialVector))
	decrypted = make([]byte, len(crypt))
	ecb.CryptBlocks(decrypted, crypt)
	//Trim decrypted result
	decrypted = PKCS5Trimming(decrypted)
	return
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}
