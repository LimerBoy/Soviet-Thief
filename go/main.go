// Author github.com/Goodies365/YandexDecrypt
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	localAppDataPath, err := os.UserCacheDir()
	if err != nil {
		panic(err)
	}

	userDataPath := filepath.Join(localAppDataPath, "Yandex/YandexBrowser/User Data")

	yadecrypt, err := newYandexDecrypt(userDataPath)
	if err != nil {
		panic(err)
	}

	yadecrypt.PrintCredentials()

	var q string
	fmt.Scan(&q)
}
