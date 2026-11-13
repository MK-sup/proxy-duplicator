package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"testing"
)

func TestFrameRoundtrip(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 1234)
	in, err := NewFrame(TypeData, 42, 7, payload)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Encode(&buf, in); err != nil {
		t.Fatal(err)
	}
	if got := buf.Len(); got != HeaderSize+len(payload) {
		t.Fatalf("encoded size = %d, want %d", got, HeaderSize+len(payload))
	}
	out, err := Decode(&buf, DefaultMaxPayload)
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != TypeData || out.SessionID != 42 || out.Seq != 7 {
		t.Errorf("header mismatch: %+v", out)
	}
	if !bytes.Equal(out.Payload, payload) {
		t.Errorf("payload mismatch (len %d vs %d)", len(out.Payload), len(payload))
	}
}

func TestFrameEmptyPayload(t *testing.T) {
	in, err := NewFrame(TypePing, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Encode(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := Decode(&buf, DefaultMaxPayload)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Payload) != 0 || out.Type != TypePing {
		t.Errorf("got %+v", out)
	}
}

func TestFrameValidation(t *testing.T) {
	if _, err := NewFrame(Type(0x99), 0, 0, nil); err == nil {
		t.Error("expected invalid type error")
	}
	if _, err := NewFrame(TypeData, 0, 0, make([]byte, MaxPayloadAbs+1)); err == nil {
		t.Error("expected oversize payload error")
	}
}

func TestDecodeBadMagic(t *testing.T) {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(0xdeadbeef))
	b.Write(make([]byte, HeaderSize-4))
	if _, err := Decode(&b, DefaultMaxPayload); err == nil {
		t.Fatal("expected bad magic error")
	}
}

func TestDecodePayloadOverLimit(t *testing.T) {
	var b bytes.Buffer
	hdr := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(hdr[0:4], Magic)
	hdr[4] = Version
	hdr[5] = byte(TypeData)
	binary.BigEndian.PutUint32(hdr[16:20], 5000)
	b.Write(hdr)
	b.Write(make([]byte, 5000))
	if _, err := Decode(&b, 4096); err == nil {
		t.Fatal("expected payload limit error")
	}
}

func TestDecodeTruncated(t *testing.T) {
	in, _ := NewFrame(TypeData, 1, 1, []byte("hello world"))
	raw := in.Bytes()
	for _, n := range []int{0, 5, HeaderSize - 1, HeaderSize + 3, len(raw) - 1} {
		if _, err := Decode(bytes.NewReader(raw[:n]), DefaultMaxPayload); err == nil {
			t.Errorf("n=%d: expected error", n)
		} else if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("n=%d: got %v, want EOF", n, err)
		}
	}
}

func FuzzDecode(f *testing.F) {
	good, _ := NewFrame(TypeData, 9, 3, []byte("fuzz payload"))
	f.Add(good.Bytes())
	f.Add([]byte("DPD1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		frm, err := Decode(bytes.NewReader(data), DefaultMaxPayload)
		if err != nil {
			return
		}
		// Re-encoding a decoded frame must round-trip.
		var buf bytes.Buffer
		if err := Encode(&buf, frm); err != nil {
			t.Fatalf("re-encode: %v", err)
		}
	})
}

func TestAddrRoundtrip(t *testing.T) {
	cases := []Addr{
		{Host: "192.0.2.1", Port: 443, ATYP: ATYPIPv4},
		{Host: "example.com", Port: 80, ATYP: ATYPDomain},
		{Host: "2001:db8::1", Port: 22, ATYP: ATYPIPv6},
		{Host: "no-atyp.example.org", Port: 1}, // derive
	}
	for _, in := range cases {
		enc := in.AppendTo(nil)
		got, n, err := ParseAddr(enc)
		if err != nil {
			t.Errorf("%v: %v", in, err)
			continue
		}
		if n != len(enc) {
			t.Errorf("%v: consumed %d of %d", in, n, len(enc))
		}
		if got.String() != in.String() {
			t.Errorf("got %v want %v", got, in)
		}
	}
}

func TestReadAddr(t *testing.T) {
	for _, in := range []Addr{
		{Host: "198.51.100.7", Port: 8080, ATYP: ATYPIPv4},
		{Host: "domain.example", Port: 53, ATYP: ATYPDomain},
	} {
		raw := in.AppendTo(nil)
		raw = append(raw, 0xAA, 0xBB) // trailing bytes must remain unread
		got, err := ReadAddr(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%v: %v", in, err)
		}
		if got.String() != in.String() {
			t.Errorf("got %v want %v", got, in)
		}
	}
}

func TestReadAddrTruncated(t *testing.T) {
	full := Addr{Host: "example.com", Port: 443, ATYP: ATYPDomain}.AppendTo(nil)
	for n := 0; n < len(full); n++ {
		if _, err := ReadAddr(bytes.NewReader(full[:n])); err == nil {
			t.Errorf("n=%d: expected error", n)
		}
	}
}

func TestFuzzDecodeQuick(t *testing.T) { // random corruption must never panic
	rng := rand.New(rand.NewSource(1))
	good, _ := NewFrame(TypeUDPData, 1, 1, []byte("payload"))
	base := good.Bytes()
	for i := 0; i < 2000; i++ {
		raw := append([]byte(nil), base...)
		for k := 0; k < 1+rng.Intn(4); k++ {
			raw[rng.Intn(len(raw))] = byte(rng.Intn(256))
		}
		_, _ = Decode(bytes.NewReader(raw), DefaultMaxPayload)
	}
}
