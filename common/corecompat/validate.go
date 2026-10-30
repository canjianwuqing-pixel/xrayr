package corecompat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// foldObject rejects ambiguous case variants before encoding/json picks a last
// value. Application data such as HTTP headers is never recursively folded.
func foldObject(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("expected config object")
	}
	result := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(token.(string))
		if _, ok := result[key]; ok {
			return nil, fmt.Errorf("duplicate config field %q", key)
		}
		var raw json.RawMessage
		if err = d.Decode(&raw); err != nil {
			return nil, err
		}
		result[key] = raw
	}
	if _, err = d.Token(); err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing config data")
	}
	return result, nil
}
func kcpRaw(handler json.RawMessage) (json.RawMessage, error) {
	h, err := foldObject(handler)
	if err != nil {
		return nil, err
	}
	stream := h["streamsettings"]
	if len(stream) == 0 || bytes.Equal(stream, []byte("null")) {
		return nil, nil
	}
	s, err := foldObject(stream)
	if err != nil {
		return nil, err
	}
	return s["kcpsettings"], nil
}
func ValidateTransportJSON(data []byte) error {
	var handlers []json.RawMessage
	if err := json.Unmarshal(data, &handlers); err != nil {
		return err
	}
	for i, h := range handlers {
		raw, err := kcpRaw(h)
		if err != nil {
			return fmt.Errorf("handler %d: %w", i, err)
		}
		if len(raw) > 0 {
			if _, err = decodeLegacyKCP(raw); err != nil {
				return fmt.Errorf("handler %d: %w", i, err)
			}
		}
	}
	return nil
}
