package corecompat

import (
	"encoding/json"
	"fmt"
)

// ValidateTransportJSON prevents the target conf structs from silently ignoring
// removed mKCP tuning fields. No equivalent tuning is guessed automatically.
func ValidateTransportJSON(data []byte) error {
	var handlers []struct {
		Stream struct {
			KCP map[string]json.RawMessage `json:"kcpSettings"`
		} `json:"streamSettings"`
	}
	if err := json.Unmarshal(data, &handlers); err != nil {
		return err
	}
	for i, h := range handlers {
		for _, field := range []string{"congestion", "readBufferSize", "writeBufferSize"} {
			if _, ok := h.Stream.KCP[field]; ok {
				return fmt.Errorf("handler %d: legacy kcpSettings.%s has no exact 26.7.28 equivalent; explicit compatibility review required", i, field)
			}
		}
	}
	return nil
}
