// Package cookie provides encrypted HTTP cookie management with automatic
// expiration handling. It uses AES-256-GCM encryption to securely store
// cookie data with embedded timestamps for expiration validation.
//
// Cookies must be initialized with New before use. Each cookie configuration
// maintains its own encryption key and is stored in memory for the lifetime
// of the application.
//
// Example usage:
//
//	// Initialize a cookie with 1 hour expiration
//	err := cookie.New("session", 3600)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Save encrypted data and save cookie in http.Response
//	data := []byte("user123")
//	cookie.Save(w, "session", data)
//
//	// Retrieve and decrypt data from http.Request
//	data, err := cookie.Get(r, "session")
//	if err != nil {
//	    // Handle expired or invalid cookie
//	}
package cookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"time"
)

// Cookie represents an encrypted cookie configuration with its cryptographic
// parameters and metadata.
type Cookie struct {
	Name   string
	MaxAge int64
	Key    []byte
	Mode   cipher.AEAD
	Nonce  []byte
}

var (
	cookies = map[string]Cookie{}
	// ErrNotInitialized is returned when attempting to operate on a cookie
	// that hasn't been initialized with New.returned when attempting to operate on a cookie.
	ErrNotInitialized = errors.New("not initialized")
	// ErrCookieExpired is returned when retrieving a cookie whose timestamp
	// exceeds its MaxAge.
	ErrCookieExpired = errors.New("expired cookie")
	// ErrExists is returned when attempting to create a cookie with a name
	// that already exists.
	ErrExists = errors.New("cookie exists")
)

// New initializes a new encrypted cookie configuration with the given name and
// max age in seconds. It generates a random AES-256 key and nonce for encryption.
// Returns ErrExists if a cookie with the same name already exists.
func New(name string, age int64) error {
	if _, ok := cookies[name]; ok {
		return ErrExists
	}
	key := make([]byte, 32)
	rand.Read(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	cookie := Cookie{
		Name:   name,
		MaxAge: age,
		Key:    key,
		Mode:   gcm,
		Nonce:  nonce,
	}
	cookies[name] = cookie
	return nil
}

// Save add a timestamp, encrypts the provided data and timestampt, and sets it as an HTTP cookie
// in the response. The cookie is secured with HttpOnly, Secure, and SameSite flags.
// Returns ErrNotInitialized if the cookie hasn't been created with New.
func Save(w http.ResponseWriter, name string, data []byte) error {
	c, ok := cookies[name]
	if !ok {
		return ErrNotInitialized
	}
	withTS := addTimestamp(data)
	encrypted := c.Mode.Seal(nil, c.Nonce, withTS, nil)
	cookie := newCookie(c.Name, base64.StdEncoding.EncodeToString(encrypted), int(c.MaxAge))
	http.SetCookie(w, cookie)
	return nil
}

// Clear removes the cookie from the client by setting its MaxAge to -1.
// If remove is true, it also deletes the cookie configuration from memory.
// Returns ErrNotInitialized if the cookie hasn't been created with New.
func Clear(w http.ResponseWriter, name string, remove bool) error {
	c, ok := cookies[name]
	if !ok {
		return ErrNotInitialized
	}
	cookie := newCookie(c.Name, "", -1)
	http.SetCookie(w, cookie)
	if remove {
		delete(cookies, name)
	}
	return nil
}

// Get retrieves and decrypts the cookie data from the request. It verifies the
// cookie hasn't expired based on its embedded timestamp and MaxAge.
// Returns ErrNotInitialized if the cookie hasn't been created with New,
// ErrCookieExpired if the cookie has expired, or other errors for decryption failures.
func Get(r *http.Request, name string) ([]byte, error) {
	c, ok := cookies[name]
	if !ok {
		return nil, ErrNotInitialized
	}
	cookie, err := r.Cookie(c.Name)
	if err != nil {
		return nil, err
	}
	encrypted, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, err
	}

	plain, err := c.Mode.Open(nil, c.Nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}
	if expired(plain, c.MaxAge) {
		return nil, ErrCookieExpired
	}
	return plain[8:], nil
}

func newCookie(name, value string, age int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   age,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

func expired(in []byte, age int64) bool {
	unix := time.Unix(int64(binary.BigEndian.Uint64(in[:8])), 0)
	return time.Since(unix) > time.Second*time.Duration(age)
}

func addTimestamp(in []byte) []byte {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))
	return append(ts, in...)
}
