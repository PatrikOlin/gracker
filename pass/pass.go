package pass

import (
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"strings"
)

func readPasswords() []string {
	return readFile("top-10000-passwords")
}

func readSalts() []string {
	return readFile("known-salts")
}

func readFile(filename string) []string {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
	}
	str := string(b)
	return strings.Split(str, "\n")
}

func hashString(str string) string {
	bs := sha1.Sum([]byte(str))
	return fmt.Sprintf("%x", bs)
}

func hashWithSalts(str string) []string {
	var s []string
	for _, salt := range readSalts() {
		s = append(s, hashString(str+salt))
		s = append(s, hashString(salt+str))
	}
	return s
}

func CrackSha1Hash(str string, useSalt bool) string {
	for _, pass := range readPasswords() {
		if useSalt {
			for _, salted := range hashWithSalts(pass) {
				if salted == str {
					return pass
				}
			}
		} else if hashString(pass) == str {
			return pass
		}
	}
	return "PASSWORD NOT IN DATABASE"
}
