package auth

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	parameters := testPasswordParameters()
	encoded, err := HashPassword([]byte("a-secure-test-password"), parameters)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword([]byte("a-secure-test-password"), encoded)
	if err != nil || !ok {
		t.Fatalf("VerifyPassword(correct) = %v, %v", ok, err)
	}
	ok, err = VerifyPassword([]byte("a-different-password"), encoded)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("VerifyPassword accepted an incorrect password")
	}
}

func TestVerifyPasswordRejectsUnsafeEncodedParameters(t *testing.T) {
	encoded := "$argon2id$v=19$m=999999999,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$MTIzNDU2Nzg5MDEyMzQ1Ng"
	if _, err := VerifyPassword([]byte("a-secure-test-password"), encoded); err == nil {
		t.Fatal("VerifyPassword() error = nil, want unsafe parameter error")
	}
}

func TestProductionDefaultAcceptsFixedInitialAdministratorPassword(t *testing.T) {
	password := []byte("admin123456")
	encoded, err := HashPassword(password, testPasswordParameters())
	if err != nil {
		t.Fatalf("HashPassword(admin123456) error = %v", err)
	}
	ok, err := VerifyPassword(password, encoded)
	if err != nil || !ok {
		t.Fatalf("VerifyPassword(default administrator password) = %v, %v", ok, err)
	}
}

func testPasswordParameters() PasswordParameters {
	return PasswordParameters{
		MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1,
		SaltLength: 16, KeyLength: 32,
	}
}
