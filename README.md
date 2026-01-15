# cookie

A Go package for encrypted HTTP cookie management with automatic expiration handling.

## Features

- **AES-256-GCM Encryption**: Secure cookie data encryption using industry-standard cryptography
- **Automatic Expiration**: Embedded timestamps with configurable max age validation
- **Secure Defaults**: Cookies are set with `HttpOnly`, `Secure`, and `SameSite=Strict` flags
- **Simple API**: Easy-to-use functions for cookie lifecycle management

## Installation

```bash
go get github.com/devilcove/cookie
```

## Usage

### Initialize a Cookie

Before using a cookie, initialize it with a name and max age (in seconds):

```go
import "github.com/devilcove/cookie"

// Create a cookie with 1 hour expiration
err := cookie.New("session", 3600)
if err != nil {
    log.Fatal(err)
}
```

### Save Cookie Data

Encrypt and save data to a cookie:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    data := []byte("user123")
    err := cookie.Save(w, "session", data)
    if err != nil {
        http.Error(w, "Failed to save cookie", http.StatusInternalServerError)
        return
    }
}
```

### Retrieve Cookie Data

Decrypt and retrieve data from a cookie:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    data, err := cookie.Get(r, "session")
    if err == cookie.ErrCookieExpired {
        http.Error(w, "Session expired", http.StatusUnauthorized)
        return
    }
    if err != nil {
        http.Error(w, "Invalid cookie", http.StatusBadRequest)
        return
    }
    
    // Use decrypted data
    userID := string(data)
}
```

### Clear a Cookie

Remove a cookie from the client:

```go
func logoutHandler(w http.ResponseWriter, r *http.Request) {
    // Clear cookie from client, keep configuration in memory
    err := cookie.Clear(w, "session", false)
    
    // Or clear and remove configuration entirely
    err = cookie.Clear(w, "session", true)
    
    if err != nil {
        http.Error(w, "Failed to clear cookie", http.StatusInternalServerError)
        return
    }
}
```

## Complete Example

```go
package main

import (
    "log"
    "net/http"
    
    "github.com/devilcove/cookie"
)

func main() {
    // Initialize cookie with 24 hour expiration
    if err := cookie.New("user_session", 86400); err != nil {
        log.Fatal(err)
    }
    
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/dashboard", dashboardHandler)
    http.HandleFunc("/logout", logoutHandler)
    
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    // Authenticate user...
    userID := []byte("user123")
    
    if err := cookie.Save(w, "user_session", userID); err != nil {
        http.Error(w, "Login failed", http.StatusInternalServerError)
        return
    }
    
    w.Write([]byte("Logged in successfully"))
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    data, err := cookie.Get(r, "user_session")
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    
    w.Write([]byte("Welcome, " + string(data)))
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    cookie.Clear(w, "user_session", false)
    w.Write([]byte("Logged out successfully"))
}
```

## Error Handling

The package provides specific error types for common scenarios:

- `cookie.ErrNotInitialized`: Cookie hasn't been initialized with `New()`
- `cookie.ErrCookieExpired`: Cookie timestamp exceeds its max age
- `cookie.ErrExists`: Attempted to create a cookie that already exists

## Security Features

- **AES-256-GCM**: Authenticated encryption with associated data
- **Random Key Generation**: Each cookie gets a unique 256-bit encryption key
- **Random Nonce**: Cryptographically secure nonce generation
- **HttpOnly Flag**: Prevents JavaScript access to cookies
- **Secure Flag**: Ensures cookies are only sent over HTTPS
- **SameSite Strict**: Protects against CSRF attacks
- **Timestamp Validation**: Automatic expiration checking on retrieval

## Limitations

- Cookie configurations are stored in memory and don't persist across application restarts
- The same nonce is reused for a given cookie configuration (consider rotating for long-lived applications)
- Maximum cookie size is limited by browser constraints (typically 4KB)

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.