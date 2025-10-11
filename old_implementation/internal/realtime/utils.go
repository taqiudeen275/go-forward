package realtime

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// generateMessageID generates a unique message ID
func generateMessageID() string {
	timestamp := time.Now().UnixNano()
	randomBytes := make([]byte, 4)
	rand.Read(randomBytes)
	randomHex := hex.EncodeToString(randomBytes)
	return fmt.Sprintf("msg_%d_%s", timestamp, randomHex)
}

// generateTimestamp returns current timestamp
func generateTimestamp() time.Time {
	return time.Now()
}

// validateChannelName validates channel name format
func validateChannelName(name string) error {
	if name == "" {
		return fmt.Errorf("channel name cannot be empty")
	}

	if len(name) > 100 {
		return fmt.Errorf("channel name cannot exceed 100 characters")
	}

	// Check for valid characters (alphanumeric, hyphens, underscores)
	for _, char := range name {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_' || char == '.') {
			return fmt.Errorf("channel name contains invalid characters")
		}
	}

	return nil
}

// validateMessageType validates message type
func validateMessageType(msgType string) error {
	validTypes := map[string]bool{
		"message":   true,
		"broadcast": true,
		"presence":  true,
		"system":    true,
		"ping":      true,
		"pong":      true,
	}

	if !validTypes[msgType] {
		return fmt.Errorf("invalid message type: %s", msgType)
	}

	return nil
}

// sanitizeUserInput sanitizes user input to prevent XSS
func sanitizeUserInput(input string) string {
	// Basic sanitization - in production, use a proper sanitization library
	replacements := map[string]string{
		"<":  "&lt;",
		">":  "&gt;",
		"&":  "&amp;",
		"\"": "&quot;",
		"'":  "&#x27;",
	}

	result := input
	for old, new := range replacements {
		result = replaceAll(result, old, new)
	}

	return result
}

// replaceAll is a simple string replacement function
func replaceAll(s, old, new string) string {
	result := ""
	for i := 0; i < len(s); {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			result += new
			i += len(old)
		} else {
			result += string(s[i])
			i++
		}
	}
	return result
}

// formatDuration formats duration for human readability
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.0fm", d.Minutes())
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%.0fh", d.Hours())
	} else {
		return fmt.Sprintf("%.0fd", d.Hours()/24)
	}
}

// isValidUserID validates user ID format
func isValidUserID(userID string) bool {
	return userID != "" && len(userID) <= 255
}

// createSystemMessage creates a system message
func createSystemMessage(event string, payload map[string]interface{}) interfaces.Message {
	return interfaces.Message{
		ID:        generateMessageID(),
		Type:      "system",
		Event:     event,
		Payload:   payload,
		UserID:    "system",
		Timestamp: generateTimestamp(),
	}
}

// createPresenceMessage creates a presence update message
func createPresenceMessage(userID string, state map[string]interface{}) interfaces.Message {
	return interfaces.Message{
		ID:    generateMessageID(),
		Type:  "presence",
		Event: "update",
		Payload: map[string]interface{}{
			"user_id": userID,
			"state":   state,
		},
		UserID:    "system",
		Timestamp: generateTimestamp(),
	}
}

// createErrorMessage creates an error message
func createErrorMessage(errorMsg string) interfaces.Message {
	return interfaces.Message{
		ID:    generateMessageID(),
		Type:  "error",
		Event: "error",
		Payload: map[string]interface{}{
			"error": errorMsg,
		},
		UserID:    "system",
		Timestamp: generateTimestamp(),
	}
}
