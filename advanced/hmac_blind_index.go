// Description: Securely store national ID numbers and support partial search using HMAC blind indexing with n-gram tokenization
// Tags: hmac, blind-index, ngram, aes-gcm, encryption, database, search, security, privacy

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
//	Security properties:
//	  - The blind index leaks only approximate structure (n-gram frequency),
//	    not the plaintext ID — as long as the HMAC key stays secret.
//	  - Two separate keys: one for encryption, one for HMAC. Compromise of
//	    one key does not compromise the other.
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
	// Generate two independent 256-bit keys.
	// In production load these from a KMS (AWS KMS, HashiCorp Vault, etc.).
	encKey := make([]byte, 32)
	hmacKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, encKey); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(rand.Reader, hmacKey); err != nil {
		panic(err)
	}

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
