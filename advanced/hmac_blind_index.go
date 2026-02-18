// Description: Securely store national ID numbers and support partial search using HMAC blind indexing with n-gram tokenization
// Tags: hmac, blind-index, ngram, aes-gcm, encryption, database, search, security, privacy, kdf

// Problem: How do you store sensitive national ID numbers and still support partial search?
//
// Naive approaches and why they fail:
//   - Plaintext storage      → data breach exposes all IDs
//   - Hashing (SHA/bcrypt)   → exact match only, partial search impossible
//   - Symmetric encryption   → you must decrypt every row to search
//
// Solution: HMAC Blind Indexing + N-gram tokenization
//
//	Store:
//	  - AES-256-GCM ciphertext of the ID  (for secure storage and retrieval)
//	  - HMAC-SHA256 tokens of all n-grams (for partial search without plaintext)
//
//	Search:
//	  - Tokenize the query into n-grams
//	  - Compute HMAC of each n-gram
//	  - Look up tokens in the blind index table
//	  - Decrypt matched records to return plaintext results
//
// Real-world key management flow:
//
//  1. Generate a single master key once (keep it secret, never commit it):
//       openssl rand -hex 32
//
//  2. Store it in .env (local dev) or a secrets manager (production):
//       APP_SECRET_KEY=a3f1... (64 hex chars = 32 bytes)
//
//  3. On app startup, load the master key and DERIVE separate subkeys
//     for each purpose using a KDF (Key Derivation Function).
//     Never use the raw master key directly for encryption or HMAC.
//     Never reuse the same key for two different purposes.
//
//  4. The derived keys are ephemeral — they live only in memory.
//     Only APP_SECRET_KEY ever touches disk/env.
//
// Why key derivation (KDF) instead of two env vars?
//   - One secret to manage, rotate, and audit.
//   - The context string guarantees the two subkeys are cryptographically
//     independent: learning encKey tells you nothing about hmacKey.
//   - deriveKey below is a simplified HKDF-Expand (RFC 5869).
//     For production, use golang.org/x/crypto/hkdf for the full spec.
//
// Security properties:
//   - The blind index leaks only approximate structure (n-gram frequency),
//     not the plaintext ID — as long as the HMAC key stays secret.
//   - Compromise of encKey does not compromise hmacKey, and vice versa.
//
// Complexity:
//
//	N-gram generation (per record):
//	  O(L²) general case — L = ID length, iterating all substring lengths.
//	  O(1)  fixed-length IDs (e.g. Thai 13-digit ID always produces 51 tokens).
//
//	Search — this code (in-memory linear scan):
//	  O(N × K)  →  effectively O(N)
//	  N = number of records, K = tokens per record (constant for fixed-length IDs).
//
//	Search — production database with an index on the token column:
//	  O(log N)  with a B-tree index  (PostgreSQL/MySQL default)
//	  O(1) avg  with a hash index
//	  e.g. CREATE INDEX idx_blind_tokens ON national_id_tokens(token);
//	       SELECT user_id FROM national_id_tokens WHERE token = $1;
//	  This is why blind tokens belong in a separate indexed child table,
//	  not stored as a JSON array or concatenated string in a single column.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

const (
	minNgramLen = 3 // shortest searchable substring
	maxNgramLen = 8 // longest searchable substring
)

// Record mirrors what you would persist in a database.
// BlindIndex would be a child table with a foreign key in a real DB.
type Record struct {
	UserID      int
	EncryptedID string   // base64(AES-256-GCM ciphertext)
	Nonce       string   // base64(GCM nonce)
	BlindIndex  []string // hex(HMAC-SHA256) of each n-gram
}

// encrypt encrypts plaintext with AES-256-GCM using the provided key.
func encrypt(key []byte, plaintext string) (ciphertext, nonce []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	nonce = make([]byte, 12)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	ciphertext = gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return
}

// decrypt reverses encrypt, returning the original plaintext.
func decrypt(key, ciphertext, nonce []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}

	return string(plaintext)
}

// loadMasterKey reads APP_SECRET_KEY from the environment.
// It expects a 64-character hex string (32 bytes).
// If not set, it prints a setup hint and exits — fail fast at startup,
// never silently fall back to a weak or hardcoded key.
func loadMasterKey() []byte {
	raw := os.Getenv("APP_SECRET_KEY")
	if raw == "" {
		fmt.Fprintln(os.Stderr, "APP_SECRET_KEY is not set.")
		fmt.Fprintln(os.Stderr, "Generate one with:")
		fmt.Fprintln(os.Stderr, "  openssl rand -hex 32")
		fmt.Fprintln(os.Stderr, "Then export it or add to .env:")
		fmt.Fprintln(os.Stderr, "  APP_SECRET_KEY=<output above>")
		fmt.Fprintln(os.Stderr, "Run the demo:")
		fmt.Fprintln(os.Stderr, "  APP_SECRET_KEY=$(openssl rand -hex 32) go run advanced/hmac_blind_index.go")
		os.Exit(1)
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid APP_SECRET_KEY (expected hex): %v\n", err)
		os.Exit(1)
	}
	if len(key) != 32 {
		fmt.Fprintln(os.Stderr, "APP_SECRET_KEY must be exactly 32 bytes (64 hex chars)")
		os.Exit(1)
	}
	return key
}

// deriveKey derives a purpose-specific subkey from the master key.
// The context string MUST be unique per use case — it is the only thing
// that separates encKey from hmacKey when both come from the same master.
//
// Internally this is HMAC-SHA256(masterKey, context), which is equivalent
// to the HKDF-Expand step (RFC 5869) for a single 32-byte output block.
// For outputs longer than 32 bytes use golang.org/x/crypto/hkdf instead.
func deriveKey(masterKey []byte, context string) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte(context))
	return mac.Sum(nil) // 32 bytes — perfect for AES-256 and HMAC-SHA256
}

// blindToken computes HMAC-SHA256 of value using the provided HMAC key.
// This is the core primitive: same input always produces the same token,
// but without the key the token reveals nothing about the value.
func blindToken(hmacKey []byte, value string) string {
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// generateNgrams returns all substrings of s whose length is between
// minLen and maxLen. For "12345" with min=3, max=4:
//
//	["123", "234", "345", "1234", "2345"]
func generateNgrams(s string, minLen, maxLen int) []string {
	runes := []rune(s)
	n := len(runes)

	var ngrams []string
	for length := minLen; length <= maxLen && length <= n; length++ {
		for i := 0; i <= n-length; i++ {
			ngrams = append(ngrams, string(runes[i:i+length]))
		}
	}
	return ngrams
}

// storeNationalID builds a Record ready for database insertion.
// encKey is used for AES-GCM, hmacKey is used for the blind index.
// These MUST be different keys stored separately.
func storeNationalID(encKey, hmacKey []byte, userID int, nationalID string) Record {
	ct, nonce := encrypt(encKey, nationalID)

	ngrams := generateNgrams(nationalID, minNgramLen, maxNgramLen)
	index := make([]string, len(ngrams))
	for i, ng := range ngrams {
		index[i] = blindToken(hmacKey, ng)
	}

	return Record{
		UserID:      userID,
		EncryptedID: base64.StdEncoding.EncodeToString(ct),
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		BlindIndex:  index,
	}
}

// searchByPartialID returns all records whose national ID contains the query
// as a substring. The search is performed entirely on blind tokens —
// no decryption happens during the search phase.
func searchByPartialID(hmacKey []byte, records []Record, query string) []Record {
	if len([]rune(query)) < minNgramLen {
		fmt.Printf("Query %q is shorter than minimum n-gram length (%d)\n", query, minNgramLen)
		return nil
	}

	token := blindToken(hmacKey, query)

	var results []Record
	for _, r := range records {
		for _, idx := range r.BlindIndex {
			if idx == token {
				results = append(results, r)
				break
			}
		}
	}
	return results
}

// decryptRecord decrypts a Record's national ID using the encryption key.
// Call this only after search to reveal plaintext to authorised consumers.
func decryptRecord(encKey []byte, r Record) string {
	ct, err := base64.StdEncoding.DecodeString(r.EncryptedID)
	if err != nil {
		panic(err)
	}
	nonce, err := base64.StdEncoding.DecodeString(r.Nonce)
	if err != nil {
		panic(err)
	}
	return decrypt(encKey, ct, nonce)
}

func main() {
	// Step 1: Load the single master key from the environment.
	//   Local dev:   source .env && go run ...
	//   Docker:      env_file: [.env] in docker-compose.yml
	//   Kubernetes:  envFrom: secretRef in the pod spec
	//   AWS/GCP:     inject via Secrets Manager / Secret Manager at deploy time
	masterKey := loadMasterKey()

	// Step 2: Derive purpose-specific subkeys. Only these derived keys are
	// used for actual crypto operations — masterKey stays in memory only
	// for this derivation step.
	encKey := deriveKey(masterKey, "national-id:encryption:v1")
	hmacKey := deriveKey(masterKey, "national-id:blind-index:v1")
	// The ":v1" suffix lets you version keys — bump to ":v2" during rotation
	// and re-encrypt records in a background migration job.
	fmt.Printf("Keys derived from APP_SECRET_KEY  encKey=%x...  hmacKey=%x...\n\n",
		encKey[:4], hmacKey[:4])

	// Sample Thai national IDs (13 digits). The same pattern applies to any
	// ID format: passport numbers, SSNs, driving licence numbers, etc.
	users := []struct {
		id       int
		national string
	}{
		{1, "1234567890123"},
		{2, "9876543210987"},
		{3, "1111222233334"},
		{4, "5555123456789"},
	}

	// --- Storage phase ---
	fmt.Println("=== Storing records ===")
	records := make([]Record, len(users))
	for i, u := range users {
		records[i] = storeNationalID(encKey, hmacKey, u.id, u.national)
		fmt.Printf("User %d stored — %d blind-index tokens generated, ciphertext: %s...\n",
			u.id, len(records[i].BlindIndex), records[i].EncryptedID[:16])
	}

	// --- Search phase ---
	fmt.Println("\n=== Partial search demo ===")
	queries := []string{
		"234",      // appears in user 1 and user 4
		"9876",     // appears in user 2 only
		"11112222", // appears in user 3 only
		"999",      // appears in no record
		"12",       // too short — below minNgramLen
	}

	for _, q := range queries {
		results := searchByPartialID(hmacKey, records, q)
		fmt.Printf("Search %q → %d match(es)\n", q, len(results))
		for _, r := range results {
			plainID := decryptRecord(encKey, r)
			fmt.Printf("  user_id=%d  national_id=%s\n", r.UserID, plainID)
		}
	}
}
