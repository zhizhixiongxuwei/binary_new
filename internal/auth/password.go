package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	MinimumAcceptedPasswordBytes = 8
	DefaultMinimumPasswordBytes  = 11
	MaximumPasswordBytes         = 1024
)

type PasswordParameters struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func DefaultPasswordParameters() PasswordParameters {
	return PasswordParameters{
		MemoryKiB:   64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func (p PasswordParameters) Validate() error {
	if p.MemoryKiB < 8*1024 || p.MemoryKiB > 1024*1024 {
		return errors.New("Argon2id memory must be between 8 MiB and 1 GiB")
	}
	if p.Iterations < 1 || p.Iterations > 20 {
		return errors.New("Argon2id iterations must be between 1 and 20")
	}
	if p.Parallelism < 1 || p.Parallelism > 16 {
		return errors.New("Argon2id parallelism must be between 1 and 16")
	}
	if p.SaltLength < 16 || p.SaltLength > 64 || p.KeyLength < 16 || p.KeyLength > 64 {
		return errors.New("Argon2id salt and key lengths are outside the accepted range")
	}
	return nil
}

func HashPassword(password []byte, parameters PasswordParameters) (string, error) {
	return HashPasswordWithMinimum(
		password,
		parameters,
		DefaultMinimumPasswordBytes,
	)
}

// HashPasswordWithMinimum applies the caller's configured creation policy.
// Verification accepts the wider supported range so a deliberately relaxed
// loopback-only development policy does not weaken production defaults.
func HashPasswordWithMinimum(
	password []byte,
	parameters PasswordParameters,
	minimumBytes int,
) (string, error) {
	if err := parameters.Validate(); err != nil {
		return "", err
	}
	if err := ValidatePasswordMinimum(minimumBytes); err != nil {
		return "", err
	}
	if err := validatePasswordLength(password, minimumBytes); err != nil {
		return "", err
	}
	salt := make([]byte, parameters.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey(password, salt, parameters.Iterations, parameters.MemoryKiB, parameters.Parallelism, parameters.KeyLength)
	base64Encoding := base64.RawStdEncoding
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		parameters.MemoryKiB,
		parameters.Iterations,
		parameters.Parallelism,
		base64Encoding.EncodeToString(salt),
		base64Encoding.EncodeToString(key),
	), nil
}

func VerifyPassword(password []byte, encoded string) (bool, error) {
	if err := validatePasswordLength(password, MinimumAcceptedPasswordBytes); err != nil {
		return false, err
	}
	parameters, salt, expected, err := decodePasswordHash(encoded)
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey(password, salt, parameters.Iterations, parameters.MemoryKiB, parameters.Parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func decodePasswordHash(encoded string) (PasswordParameters, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return PasswordParameters{}, nil, nil, errors.New("password hash is not a supported Argon2id encoding")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return PasswordParameters{}, nil, nil, errors.New("password hash uses an unsupported Argon2id version")
	}
	values := strings.Split(parts[3], ",")
	if len(values) != 3 {
		return PasswordParameters{}, nil, nil, errors.New("password hash has invalid Argon2id parameters")
	}
	memory, err := parameterValue(values[0], "m")
	if err != nil {
		return PasswordParameters{}, nil, nil, err
	}
	iterations, err := parameterValue(values[1], "t")
	if err != nil {
		return PasswordParameters{}, nil, nil, err
	}
	parallelism, err := parameterValue(values[2], "p")
	if err != nil || parallelism > 255 {
		return PasswordParameters{}, nil, nil, errors.New("password hash has invalid Argon2id parallelism")
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return PasswordParameters{}, nil, nil, errors.New("password hash salt is not valid base64")
	}
	expected, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return PasswordParameters{}, nil, nil, errors.New("password hash key is not valid base64")
	}
	parameters := PasswordParameters{
		MemoryKiB:   uint32(memory),
		Iterations:  uint32(iterations),
		Parallelism: uint8(parallelism),
		SaltLength:  uint32(len(salt)),
		KeyLength:   uint32(len(expected)),
	}
	if err := parameters.Validate(); err != nil {
		return PasswordParameters{}, nil, nil, fmt.Errorf("password hash parameters are unsafe: %w", err)
	}
	return parameters, salt, expected, nil
}

func parameterValue(value, name string) (uint64, error) {
	prefix := name + "="
	if !strings.HasPrefix(value, prefix) {
		return 0, fmt.Errorf("password hash is missing Argon2id parameter %s", name)
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("password hash has invalid Argon2id parameter %s", name)
	}
	return parsed, nil
}

func ValidatePasswordMinimum(minimumBytes int) error {
	if minimumBytes < MinimumAcceptedPasswordBytes || minimumBytes > 128 {
		return fmt.Errorf(
			"password minimum must be between %d and 128 bytes",
			MinimumAcceptedPasswordBytes,
		)
	}
	return nil
}

func validatePasswordLength(password []byte, minimumBytes int) error {
	if len(password) < minimumBytes {
		return fmt.Errorf(
			"password must contain at least %d bytes",
			minimumBytes,
		)
	}
	if len(password) > MaximumPasswordBytes {
		return fmt.Errorf("password exceeds %d bytes", MaximumPasswordBytes)
	}
	return nil
}
