// Author github.com/Goodies365/YandexDecrypt
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"syscall"
	"unsafe"
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func decryptAesGcm256(encryptedData, key, iv, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, encryptedData, additionalData)
}

func newBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *dataBlob) bytes() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func decryptDpapi(ciphertext []byte) ([]byte, error) {
	crypt32 := syscall.NewLazyDLL("crypt32.dll")
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	unprotectDataProc := crypt32.NewProc("CryptUnprotectData")
	localFreeProc := kernel32.NewProc("LocalFree")

	var outBlob dataBlob
	r, _, err := unprotectDataProc.Call(
		uintptr(unsafe.Pointer(newBlob(ciphertext))),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed with error %w", err)
	}

	defer localFreeProc.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	return outBlob.bytes(), nil
}
