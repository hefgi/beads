package dolt

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptWithKey(t *testing.T) {
	// Generate a test key (32 bytes)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := "my-secret-password"

	encrypted, err := encryptWithKey([]byte(plaintext), key)
	if err != nil {
		t.Fatalf("encryptWithKey failed: %v", err)
	}

	if len(encrypted) == 0 {
		t.Fatal("encrypted output is empty")
	}

	decrypted, err := decryptWithKey(encrypted, key)
	if err != nil {
		t.Fatalf("decryptWithKey failed: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptWithWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 1)
	}

	encrypted, err := encryptWithKey([]byte("secret"), key1)
	if err != nil {
		t.Fatalf("encryptWithKey failed: %v", err)
	}

	_, err = decryptWithKey(encrypted, key2)
	if err == nil {
		t.Fatal("decryptWithKey should fail with wrong key")
	}
}

func TestEncryptionKeyPath(t *testing.T) {
	store := &DoltStore{dbPath: "/home/user/.beads/dolt"}
	got := store.encryptionKeyPath()
	want := filepath.Join("/home/user/.beads", ".encryption_key")
	if got != want {
		t.Fatalf("encryptionKeyPath: got %q, want %q", got, want)
	}
}

func TestEncryptionKeyFileRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "dolt")
	if err := os.MkdirAll(dbPath, 0700); err != nil {
		t.Fatal(err)
	}

	store := &DoltStore{dbPath: dbPath}

	// No key file yet — encryptionKey() should fail
	_, err := store.encryptionKey()
	if err == nil {
		t.Fatal("encryptionKey should fail when no key file exists and no cached key")
	}

	// Write a valid key file
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}
	keyPath := store.encryptionKeyPath()
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}

	// Now it should succeed
	got, err := store.encryptionKey()
	if err != nil {
		t.Fatalf("encryptionKey failed after writing key file: %v", err)
	}

	if len(got) != 32 {
		t.Fatalf("key length: got %d, want 32", len(got))
	}

	// Verify the key matches what we wrote
	for i := range key {
		if got[i] != key[i] {
			t.Fatalf("key mismatch at byte %d: got %d, want %d", i, got[i], key[i])
		}
	}

	// Verify file permissions
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key file permissions: got %o, want 0600", info.Mode().Perm())
	}
}

func TestLegacyEncryptionKeyIsDeterministic(t *testing.T) {
	store := &DoltStore{dbPath: "/home/user/.beads/dolt"}

	key1 := store.legacyEncryptionKey()
	key2 := store.legacyEncryptionKey()

	if len(key1) != 32 {
		t.Fatalf("legacy key length: got %d, want 32", len(key1))
	}

	for i := range key1 {
		if key1[i] != key2[i] {
			t.Fatal("legacy key is not deterministic")
		}
	}
}

func TestLegacyToNewKeyMigration(t *testing.T) {
	// Encrypt with legacy key, verify we can decrypt after re-encryption with new key
	legacyKey := func() []byte {
		store := &DoltStore{dbPath: "/test/path"}
		return store.legacyEncryptionKey()
	}()

	password := "federation-secret-123"

	// Encrypt with legacy key
	encrypted, err := encryptWithKey([]byte(password), legacyKey)
	if err != nil {
		t.Fatalf("encrypt with legacy key: %v", err)
	}

	// Decrypt with legacy key (simulating migration read)
	decrypted, err := decryptWithKey(encrypted, legacyKey)
	if err != nil {
		t.Fatalf("decrypt with legacy key: %v", err)
	}
	if decrypted != password {
		t.Fatalf("legacy decrypt: got %q, want %q", decrypted, password)
	}

	// Re-encrypt with new random key (simulating migration write)
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 42)
	}

	reEncrypted, err := encryptWithKey([]byte(decrypted), newKey)
	if err != nil {
		t.Fatalf("re-encrypt with new key: %v", err)
	}

	// Decrypt with new key
	finalDecrypted, err := decryptWithKey(reEncrypted, newKey)
	if err != nil {
		t.Fatalf("decrypt with new key: %v", err)
	}
	if finalDecrypted != password {
		t.Fatalf("new key decrypt: got %q, want %q", finalDecrypted, password)
	}
}

func TestEncryptPasswordEmptyString(t *testing.T) {
	store := &DoltStore{encKey: make([]byte, 32)}

	encrypted, err := store.encryptPassword("")
	if err != nil {
		t.Fatalf("encryptPassword empty: %v", err)
	}
	if encrypted != nil {
		t.Fatal("encryptPassword should return nil for empty password")
	}
}

func TestDecryptPasswordEmptySlice(t *testing.T) {
	store := &DoltStore{encKey: make([]byte, 32)}

	decrypted, err := store.decryptPassword(nil)
	if err != nil {
		t.Fatalf("decryptPassword nil: %v", err)
	}
	if decrypted != "" {
		t.Fatalf("decryptPassword nil: got %q, want empty", decrypted)
	}

	decrypted, err = store.decryptPassword([]byte{})
	if err != nil {
		t.Fatalf("decryptPassword empty: %v", err)
	}
	if decrypted != "" {
		t.Fatalf("decryptPassword empty: got %q, want empty", decrypted)
	}
}

func TestEncryptDecryptPasswordRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	store := &DoltStore{encKey: key}

	password := "test-federation-password"

	encrypted, err := store.encryptPassword(password)
	if err != nil {
		t.Fatalf("encryptPassword: %v", err)
	}

	decrypted, err := store.decryptPassword(encrypted)
	if err != nil {
		t.Fatalf("decryptPassword: %v", err)
	}

	if decrypted != password {
		t.Fatalf("round-trip: got %q, want %q", decrypted, password)
	}
}

func TestInvalidKeyFileLength(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "dolt")
	if err := os.MkdirAll(dbPath, 0700); err != nil {
		t.Fatal(err)
	}

	store := &DoltStore{dbPath: dbPath}

	// Write a key file with wrong length
	keyPath := store.encryptionKeyPath()
	if err := os.WriteFile(keyPath, []byte("too-short"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := store.encryptionKey()
	if err == nil {
		t.Fatal("encryptionKey should fail with invalid key length")
	}
}
