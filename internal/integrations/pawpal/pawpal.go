package pawpal

import (
	"crypto/subtle"
	"fmt"
	"math"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
)

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(payload any, providedKey, expectedKey string) WebhookVerification {
	payloadRecord, ok := payload.(map[string]any)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed, OrderID: 0}
	}
	orderID, ok := payloadRecord["orderId"].(float64)
	if !ok ||
		orderID <= 0 ||
		orderID > 9007199254740991 ||
		payloadRecord["status"] != "approved" ||
		math.Trunc(orderID) != orderID {
		return WebhookVerification{Outcome: WebhookMalformed, OrderID: int64(orderID)}
	}

	match := subtle.ConstantTimeCompare([]byte(providedKey), []byte(expectedKey))
	if match != 1 {
		return WebhookVerification{Outcome: WebhookUnauthorized, OrderID: int64(orderID)}
	}

	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
