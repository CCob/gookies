package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/net/publicsuffix"
)

var (
	dllcrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")
)

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

// Cookie - Items for a cookie
type Cookie struct {
	Domain         string
	Key            string
	Value          string
	EncryptedValue []byte
}

var profile string

func ifThenElse(condition bool, a interface{}, b interface{}) interface{} {
	if condition {
		return a
	}
	return b
}

func newBlob(d []byte) *DATA_BLOB {
	if len(d) == 0 {
		return &DATA_BLOB{}
	}
	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DATA_BLOB) toByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func (c *Cookie) decryptCookie() string {
	if c.Value > "" {
		return c.Value
	}

	if len(c.EncryptedValue) > 0 {
		var decryptedValue, _ = decryptValue(c.EncryptedValue)
		return string(decryptedValue)
	}

	return ""
}

func decryptValue(data []byte) ([]byte, error) {
	var outblob DATA_BLOB
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(newBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.toByteArray(), nil
}

func getDomains() []string {

	cookies := getCookies(nil)
	domains := make(map[string]bool)

	for _, cookie := range cookies {
		if cookie.Domain[0] == '.' {
			cookie.Domain = cookie.Domain[1:]
		}
		domains[cookie.Domain] = true
	}

	keys := make([]string, 0, len(domains))
	for k := range domains {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	return keys
}

func getCookies(domain *string) (cookies []Cookie) {

	var rows *sql.Rows
	var path, err = os.UserCacheDir()
	var cookiesFile = fmt.Sprintf("%s\\Google\\Chrome\\User Data\\%s\\Cookies", path, profile)

	db, err := sql.Open("sqlite3", cookiesFile)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if domain != nil {
		rows, err = db.Query("SELECT name, value, host_key, encrypted_value FROM cookies WHERE host_key = ?", fmt.Sprintf("%s", *domain))
	} else {
		rows, err = db.Query("SELECT name, value, host_key, encrypted_value FROM cookies")
	}

	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()
	for rows.Next() {
		var name, value, hostKey string
		var encryptedValue []byte
		rows.Scan(&name, &value, &hostKey, &encryptedValue)
		cookies = append(cookies, Cookie{hostKey, name, value, encryptedValue})
	}

	return
}

func getCanonicalCookieValue(domain string) string {

	tld, _ := publicsuffix.EffectiveTLDPlusOne(domain)

	if tld != "" {
		tld = fmt.Sprintf(".%s", tld)
	}

	cookies := append(getCookies(&tld), getCookies(&domain)...)
	result := ""

	for index, cookie := range cookies {
		lastCookie := index == len(cookies)-1
		result += fmt.Sprintf("%s=%s%s", cookie.Key, cookie.decryptCookie(), ifThenElse(lastCookie, "", "; "))
	}

	return result
}

func getProfiles() (result map[int]string) {

	result = make(map[int]string)
	result[0] = "Default"
	var path, _ = os.UserCacheDir()
	var userDataFolder = fmt.Sprintf("%s\\Google\\Chrome\\User Data", path)

	files, _ := ioutil.ReadDir(userDataFolder)

	for _, file := range files {
		var profileID int
		if file.IsDir() {
			_, err := fmt.Sscanf(file.Name(), "Profile %d", &profileID)
			if err == nil {

				data, _ := ioutil.ReadFile(fmt.Sprintf("%s\\%s\\Preferences", userDataFolder, file.Name()))
				var preferences map[string]interface{}
				json.Unmarshal(data, &preferences)
				result[profileID] = preferences["profile"].(map[string]interface{})["name"].(string)
			}
		}
	}

	return result
}

func main() {

	var domainName string
	profiles := false
	profileIndex := 0

	flag.BoolVar(&profiles, "profiles", false, "Lists the profile names and index to Chrome profiles under this account")
	flag.IntVar(&profileIndex, "profile", 0, "Which Chrome profile index to extract cookie data from, uses Default when not specified")
	flag.StringVar(&domainName, "domain", "", "Show the canonicalised cookie value for a specific domain")

	flag.Parse()

	if profiles {
		profileMap := getProfiles()

		for profileID, profileName := range profileMap {
			fmt.Printf("%d: %s\n", profileID, profileName)
		}

		return
	}

	if profileIndex == 0 {
		profile = "Default"
	} else {
		profile = fmt.Sprintf("Profile %d", profileIndex)
	}

	if domainName == "" {

		domains := getDomains()

		for _, domain := range domains {
			fmt.Printf("Domain: %s\n", domain)
		}

	} else {
		fmt.Printf("Cookies: %s\n", getCanonicalCookieValue(domainName))
	}
}
