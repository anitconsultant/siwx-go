package main

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/anitconsultant/siwx-go/siwx"
)

// problem is an RFC 7807 problem-details response.
type problem struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail"`
	Instance string `json:"instance,omitempty"`
}

// writeProblem writes an RFC 7807 JSON response from an error.
// Detail is always generic — internal specifics are emitted to slog only.
func writeProblem(c *gin.Context, err error, requestID string) {
	p := problemForErr(err)
	p.Instance = requestID
	c.JSON(p.Status, p)
}

func problemForErr(err error) problem {
	switch {
	case errors.Is(err, siwx.ErrMalformed):
		return problem{
			Type:   "/problems/malformed-message",
			Title:  "Malformed message",
			Status: http.StatusBadRequest,
			Detail: "The sign-in message could not be parsed.",
		}
	case errors.Is(err, siwx.ErrDomainMismatch):
		return problem{
			Type:   "/problems/domain-mismatch",
			Title:  "Domain mismatch",
			Status: http.StatusUnauthorized,
			Detail: "The domain in the sign-in message does not match this server.",
		}
	case errors.Is(err, siwx.ErrNonceMismatch):
		return problem{
			Type:   "/problems/nonce-check-failed",
			Title:  "Nonce check failed",
			Status: http.StatusUnauthorized,
			Detail: "The nonce is invalid, expired, or already used.",
		}
	case errors.Is(err, siwx.ErrExpired):
		return problem{
			Type:   "/problems/message-expired",
			Title:  "Message expired",
			Status: http.StatusUnauthorized,
			Detail: "The sign-in message has expired.",
		}
	case errors.Is(err, siwx.ErrNotYetValid):
		return problem{
			Type:   "/problems/not-yet-valid",
			Title:  "Not yet valid",
			Status: http.StatusUnauthorized,
			Detail: "The sign-in message is not yet valid.",
		}
	case errors.Is(err, siwx.ErrBadSignature):
		return problem{
			Type:   "/problems/signature-invalid",
			Title:  "Signature invalid",
			Status: http.StatusUnauthorized,
			Detail: "The wallet signature could not be verified.",
		}
	case errors.Is(err, siwx.ErrUnsupportedNamespace):
		return problem{
			Type:   "/problems/unsupported-namespace",
			Title:  "Unsupported namespace",
			Status: http.StatusUnprocessableEntity,
			Detail: "The requested chain namespace is not supported.",
		}
	default:
		return problem{
			Type:   "/problems/internal-error",
			Title:  "Internal server error",
			Status: http.StatusInternalServerError,
			Detail: "An unexpected error occurred.",
		}
	}
}
