package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
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

	pCryptUnprotectData = dllcrypt32.NewProc("CryptUnprotectData")
	pLocalFree          = dllkernel32.NewProc("LocalFree")
)

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

// Cookie - Items for a cookie
type Cookie struct {
	Domain         string `json:"domain"`
	ExpirationDate int64  `json:"expirationDate"`
	HostOnly       bool   `json:"hostOnly"`
	HttpOnly       bool   `json:"httpOnly"`
	Name           string `json:"name"`
	Path           string `json:"path"`
	SameSite       string `json:"sameSite"`
	Secure         bool   `json:"secure"`
	Session        bool   `json:"session"`
	Value          string `json:"value"`
	StoreId        string `json:"storeId"`
	ID             int    `json:"id"`
	EncryptedValue []byte `json:"-"`
}

var profile, storeId string
var aesKey []byte

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

func (c *Cookie) decryptCookie() {
	if c.Value > "" {
		return
	}

	if len(c.EncryptedValue) > 0 {
		var decryptedValue, _ = decryptValue(c.EncryptedValue)
		c.Value = string(decryptedValue)
	}
}

func getAesGCMKey() []byte {

	var encryptedKey []byte
	var path, _ = os.UserCacheDir()
	var localStateFile = fmt.Sprintf("%s\\Google\\Chrome\\User Data\\Local State", path)

	data, _ := ioutil.ReadFile(localStateFile)
	var localState map[string]interface{}
	json.Unmarshal(data, &localState)

	if localState["os_crypt"] != nil {

		encryptedKey, _ = base64.StdEncoding.DecodeString(localState["os_crypt"].(map[string]interface{})["encrypted_key"].(string))

		if bytes.Equal(encryptedKey[0:5], []byte{'D', 'P', 'A', 'P', 'I'}) {
			encryptedKey, _ = decryptValue(encryptedKey[5:])
		} else {
			fmt.Print("encrypted_key does not look like DPAPI key\n")
		}
	}

	return encryptedKey
}

func decryptValue(data []byte) ([]byte, error) {

	if bytes.Equal(data[0:3], []byte{'v', '1', '0'}) {

		aesBlock, _ := aes.NewCipher(aesKey)
		aesgcm, _ := cipher.NewGCM(aesBlock)

		nonce := data[3:15]
		encryptedData := data[15:]

		plaintext, _ := aesgcm.Open(nil, nonce, encryptedData, nil)

		return plaintext, nil

	} else {

		var outblob DATA_BLOB
		r, _, err := pCryptUnprotectData.Call(uintptr(unsafe.Pointer(newBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
		if r == 0 {
			return nil, err
		}
		defer pLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
		return outblob.toByteArray(), nil
	}
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

	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?cache=shared&mode=ro", cookiesFile))
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()

	if domain != nil {
		rows, err = db.Query("SELECT host_key as Domain, expires_utc as ExpirationDate, is_httponly as HttpOnly, name as Name, path as Path, samesite as SameSite, "+
			"is_secure as Secure, is_persistent as Session, value as Value, encrypted_value as EncryptedValue FROM cookies WHERE Domain LIKE ?", fmt.Sprintf("%%%s", *domain))
	} else {
		rows, err = db.Query("SELECT name, value, host_key, encrypted_value FROM cookies")
	}

	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()
	index := int(1)
	for rows.Next() {

		var cookie Cookie
		var sameSite, secure, session, httpOnly int

		rows.Scan(&cookie.Domain, &cookie.ExpirationDate, &httpOnly, &cookie.Name,
			&cookie.Path, &sameSite, &secure, &session, &cookie.Value, &cookie.EncryptedValue)

		cookie.SameSite = "unspecified"
		cookie.Session = session == 0
		cookie.HttpOnly = httpOnly == 1
		cookie.Secure = secure == 1
		cookie.StoreId = storeId
		cookie.ID = index
		cookie.ExpirationDate = (cookie.ExpirationDate / 1000000) - 11644473600
		cookie.decryptCookie()

		cookies = append(cookies, cookie)
		index++
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
		result += fmt.Sprintf("%s=%s%s", cookie.Name, cookie.Value, ifThenElse(lastCookie, "", "; "))
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

	var domainName, format string
	profiles := false
	profileIndex := 0

	flag.BoolVar(&profiles, "profiles", false, "Lists the profile names and index to Chrome profiles under this account")
	flag.IntVar(&profileIndex, "profile", 0, "Which Chrome profile index to extract cookie data from, uses Default when not specified")
	flag.StringVar(&domainName, "domain", "", "Show the canonicalised cookie value for a specific domain")
	flag.StringVar(&storeId, "storeId", "0", "The storeId to embed in exported JSON, incognito is storeId 1 in Chrome")
	flag.StringVar(&format, "format", "json", "The output format: string, json (default)")

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

		aesKey = getAesGCMKey()

		if format == "json" {
			result, _ := json.Marshal(getCookies(&domainName))
			fmt.Print(string(result))
		} else {
			fmt.Printf("Cookies: %s\n", getCanonicalCookieValue(domainName))
		}
	}
}
