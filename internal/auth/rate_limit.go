package auth

import (
	"crypto/sha256"
	"errors"
	"net"
	"time"
)

var ErrLoginRateLimited = errors.New("login rate limit exceeded")

const (
	loginRateLimitKeyDomain = "binaryscan-login-rate-limit-v1\x00"
	loginRateLimitNoIPTag   = byte(0)
	loginRateLimitIPv4Tag   = byte(4)
	loginRateLimitIPv6Tag   = byte(6)
)

type LoginRateLimitPolicy struct {
	Threshold     uint32
	Window        time.Duration
	BlockDuration time.Duration
}

func (p LoginRateLimitPolicy) valid() bool {
	return p.Threshold > 0 &&
		p.Threshold <= 1000 &&
		p.Window >= time.Second &&
		p.Window <= time.Hour &&
		p.BlockDuration >= time.Second &&
		p.BlockDuration <= 24*time.Hour
}

type LoginAttempt struct {
	ClientKey       [sha256.Size]byte
	WindowStartedAt time.Time
	Limited         bool
	RetryAfter      time.Duration
}

type loginRateLimitedError struct {
	retryAfter time.Duration
}

func (e loginRateLimitedError) Error() string {
	return ErrLoginRateLimited.Error()
}

func (e loginRateLimitedError) Unwrap() error {
	return ErrLoginRateLimited
}

func NewLoginRateLimitedError(retryAfter time.Duration) error {
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	if retryAfter > 24*time.Hour {
		retryAfter = 24 * time.Hour
	}
	return loginRateLimitedError{retryAfter: retryAfter}
}

func LoginRateLimitRetryAfter(err error) time.Duration {
	var rateError loginRateLimitedError
	if errors.As(err, &rateError) {
		return rateError.retryAfter
	}
	return 0
}

func normalizeLoginClientKey(clientIP []byte) [sha256.Size]byte {
	material := make([]byte, 0, len(loginRateLimitKeyDomain)+17)
	material = append(material, loginRateLimitKeyDomain...)
	ip := net.IP(clientIP)
	if ipv4 := ip.To4(); ipv4 != nil {
		material = append(material, loginRateLimitIPv4Tag)
		material = append(material, ipv4...)
		return sha256.Sum256(material)
	}
	if len(clientIP) == net.IPv6len {
		if ipv6 := ip.To16(); ipv6 != nil {
			material = append(material, loginRateLimitIPv6Tag)
			material = append(material, ipv6...)
			return sha256.Sum256(material)
		}
	}
	material = append(material, loginRateLimitNoIPTag)
	return sha256.Sum256(material)
}

func loginRateLimitRetention(policy LoginRateLimitPolicy) time.Duration {
	retention := policy.Window
	if policy.BlockDuration > retention {
		retention = policy.BlockDuration
	}
	return 2 * retention
}

func retryAfterDuration(until, now time.Time) time.Duration {
	if !until.After(now) {
		return time.Second
	}
	value := until.Sub(now)
	return ((value + time.Second - 1) / time.Second) * time.Second
}
