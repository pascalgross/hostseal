package agent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// decodeSignature decodes a base64 signature from the wire.
//
// It accepts only standard base64, not the URL-safe alphabet. Accepting both would mean two encodings
// of the same signature, and a canonical protocol with two spellings of a field is a protocol with an
// interoperability bug waiting for the second implementation.
func decodeSignature(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, fmt.Errorf("agent: the signed payload carries no signature")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("agent: the signature is not valid base64: %w", err)
	}
	return raw, nil
}

// jsonRecord encodes a value for writing to disk, indented so a human can read it in an incident.
func jsonRecord(v any) ([]byte, error) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("agent: encoding a record: %w", err)
	}
	return append(raw, '\n'), nil
}
