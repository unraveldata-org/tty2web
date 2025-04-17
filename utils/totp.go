package utils

import (
	"log"
	"time"

	"github.com/xlzd/gotp"
)

var (
	otpSecret   = ""
	otpInterval = 3600 // 1 hour
)

// SetOTPSecret sets the OTP secret for the application.
func SetOTPSecret(secret string, debug bool) {
	otpSecret = secret
	if debug {
		totp := gotp.NewTOTP(
			otpSecret,
			6,
			otpInterval,
			nil,
		)
		// Generate a new OTP and print it
		otpCode := totp.Now()
		// Print the OTP code
		log.Println("OTP code:", otpCode)
	}
}

func VerifyOTP(token string) bool {
	if otpSecret == "" {
		return false
	}

	// Implement the OTP verification logic here.
	totp := gotp.NewTOTP(
		otpSecret,
		6,
		otpInterval,
		nil,
	)

	return totp.Verify(token, time.Now().Unix())
}
