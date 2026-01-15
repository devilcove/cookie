package cookie

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Kairum-Labs/should"
)

var (
	good       []byte
	bad        []byte
	cookieName = "cookie-testing"
)

type CookieData struct {
	Name string
	ID   int
}

func TestMain(m *testing.M) {
	var err error
	log.SetFlags(log.Lshortfile)
	bad = []byte("testing")
	good, err = json.Marshal(CookieData{Name: "hello world", ID: 42})
	if err != nil {
		os.Exit(2)
	}
	if err := New("cookie-testing", 3600); err != nil {
		os.Exit(3)
	}
	os.Exit(m.Run())
}

func TestNotInitalized(t *testing.T) {
	t.Run("Save", func(t *testing.T) {
		w := httptest.NewRecorder()
		should.BeErrorIs(t, Save(w, "notinitalized", bad), ErrNotInitialized)
	})
	t.Run("Get", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		_, err := Get(r, "notinitialized")
		should.BeErrorIs(t, err, ErrNotInitialized)
	})
	t.Run("Clear", func(t *testing.T) {
		w := httptest.NewRecorder()
		should.BeErrorIs(t, Clear(w, "notinitialized", false), ErrNotInitialized)
	})
}

func TestCookies(t *testing.T) {
	t.Run("alreadyCreated", func(t *testing.T) {
		should.BeErrorIs(t, New(cookieName, 3600), ErrExists)
	})
	t.Run("getNotSet", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		data, err := Get(r, cookieName)
		should.BeErrorIs(t, err, http.ErrNoCookie)
		should.BeEmpty(t, data)
	})

	t.Run("setCookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		should.NotBeError(t, Save(w, cookieName, good))
		io.WriteString(w, "cookie set")
		for _, cookie := range w.Result().Cookies() {
			should.NotBeError(t, cookie.Valid())
			should.BeEqual(t, cookie.Name, cookieName)
		}
		body, err := io.ReadAll(w.Result().Body)
		should.NotBeError(t, err)
		should.BeEqual(t, strings.TrimSpace(string(body)), "cookie set")
	})

	t.Run("getSet", func(t *testing.T) {
		w := httptest.NewRecorder()
		should.NotBeError(t, Save(w, cookieName, good))

		// setCookie(w, r)
		cookies := w.Result().Cookies()
		for _, cookie := range cookies {
			if cookie.Name == cookieName {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.AddCookie(cookie)
				data, err := Get(r, cookieName)
				should.NotBeError(t, err)
				should.BeEqual(t, data, good)
			}
		}
	})

	t.Run("badencryption", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		cookie := newCookie(cookieName, base64.StdEncoding.EncodeToString([]byte("testing")), 300)
		r.AddCookie(cookie)
		_, err := Get(r, cookieName)
		should.BeEqual(t, err.Error(), "cipher: message authentication failed")
	})

	t.Run("badHex", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		cookie := newCookie(cookieName, hex.EncodeToString([]byte("testing")), 300)
		r.AddCookie(cookie)
		_, err := Get(r, cookieName)
		var expected base64.CorruptInputError
		should.BeErrorAs(t, err, &expected)
	})

	t.Run("clear", func(t *testing.T) {
		w := httptest.NewRecorder()
		should.NotBeError(t, Clear(w, cookieName, false))
		for _, cookie := range w.Result().Cookies() {
			should.BeEqual(t, cookie.Value, "")
			should.BeEqual(t, cookie.MaxAge, -1)
		}
		_, ok := cookies[cookieName]
		should.BeTrue(t, ok)
		should.NotBeError(t, Clear(w, cookieName, true))
		_, ok = cookies[cookieName]
		should.BeFalse(t, ok)
	})

	t.Run("expiredCookie", func(t *testing.T) {
		var cookie *http.Cookie
		var found bool
		should.NotBeError(t, New("expired", 1))
		w := httptest.NewRecorder()
		should.NotBeError(t, Save(w, "expired", []byte("don't care")))
		for _, c := range w.Result().Cookies() {
			if c.Name == "expired" {
				cookie = c
				found = true
			}
		}
		should.BeTrue(t, found)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(cookie)
		data, err := Get(r, "expired")
		should.NotBeError(t, err)
		should.NotBeEmpty(t, data)
		time.Sleep(time.Second)
		data, err = Get(r, "expired")
		should.BeErrorIs(t, err, ErrCookieExpired)
		should.BeEmpty(t, data)
	})
}
