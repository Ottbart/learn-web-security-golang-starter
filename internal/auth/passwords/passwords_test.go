package passwords

import (
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	passwordHash, err := Hash("password123")
	if err != nil {
		t.Fatal(err)
	}
	if !Verify("password123", passwordHash) {
		t.Fatal("Verify() rejected the password used to create the hash")
	}
	if Verify("wrong-password", passwordHash) {
		t.Fatal("Verify() accepted the wrong password")
	}
}

func TestNeedsRehashForArgon2idParameters(t *testing.T) {
	currentHash, err := Hash("password123")
	if err != nil {
		t.Fatal(err)
	}
	if NeedsRehash(currentHash) {
		t.Fatal("NeedsRehash() marked a current-policy hash as stale")
	}

	staleHash := strings.Replace(currentHash, "m=19456,t=2,p=1", "m=12288,t=1,p=1", 1)
	if !NeedsRehash(staleHash) {
		t.Fatal("NeedsRehash() did not mark outdated Argon2id parameters as stale")
	}
}
