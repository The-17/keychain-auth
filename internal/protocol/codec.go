package protocol

import (
    "bufio"
    "encoding/json"
    "fmt"
    "io"
)

// Decoder reads newline-delimited JSON messages from a reader.
type Decoder struct {
    scanner *bufio.Scanner
}

func NewDecoder(r io.Reader) *Decoder {
    s := bufio.NewScanner(r)
    s.Buffer(make([]byte, 0, 64*1024), 64*1024) // 64KB max message size
    return &Decoder{scanner: s}
}

// ReadRaw reads the next line and returns the raw JSON bytes.
// Returns io.EOF when the connection is closed.
func (d *Decoder) ReadRaw() ([]byte, error) {
    if !d.scanner.Scan() {
        if err := d.scanner.Err(); err != nil {
            return nil, fmt.Errorf("read error: %w", err)
        }
        return nil, io.EOF
    }
    return d.scanner.Bytes(), nil
}

// Encoder writes newline-delimited JSON messages to a writer.
type Encoder struct {
    w io.Writer
}

func NewEncoder(w io.Writer) *Encoder {
    return &Encoder{w: w}
}

// Write marshals v as JSON and writes it followed by a newline.
func (e *Encoder) Write(v any) error {
    data, err := json.Marshal(v)
    if err != nil {
        return fmt.Errorf("marshal error: %w", err)
    }
    data = append(data, '\n')
    _, err = e.w.Write(data)
    return err
}
