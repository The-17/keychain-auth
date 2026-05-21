package protocol

import (
	"encoding/json"
)

// UnmarshalRequest parses raw bytes into a Request struct.
func UnmarshalRequest(raw []byte, req *Request) error {
	return json.Unmarshal(raw, req)
}
