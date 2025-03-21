package mtc

import (
	"golang.org/x/crypto/cryptobyte"

	"errors"
	"io"
	"reflect"
)

var (
	// ErrTruncated is a parsing error returned when the input seems to have
	// been truncated.
	ErrTruncated = errors.New("Input truncated")

	// ErrExtraBytes is a parsing error returned when there are extraneous
	// bytes at the end of, or within, the data.
	ErrExtraBytes = errors.New("Unexpected extra (internal) bytes")

	// ErrChecksumInvalid is an error returned when a checksum does not
	// match the corresponding data.
	ErrChecksumInvalid = errors.New("Invalid checksum")

	// Used to stop unmarshalling early
	errShortCircuit = errors.New("Short circuit")
)

type unmarshaler interface {
	// Unmarshals the receiver from the given String, advancing it as
	// necessary.
	//
	// Needs to return ErrTruncated if the given input is too short.
	//
	// Must ignore extra bytes at the end.
	unmarshal(*cryptobyte.String) error

	// Return maximum possible marshalled size.
	maxSize() int
}

// Unmarshals a single T from r.
func unmarshalOne[T unmarshaler](r io.Reader) (ret T, err error) {
	err = unmarshal(r, func(_ int, msg T) error {
		ret = msg
		return errShortCircuit
	})
	if err == errShortCircuit {
		err = nil
	}
	return
}

// Unmarshals a stream of T from r, and call f on each of them as second
// argument, with the offset in the stream as the first argument.
//
// If f returns an error, break.
func unmarshal[T unmarshaler](r io.Reader, f func(int, T) error) error {
	// Create a new instance of T
	var msg T
	reflect.ValueOf(&msg).Elem().Set(reflect.New(reflect.TypeOf(msg).Elem()))

	buf := make([]byte, 512)
	s := cryptobyte.String(buf[:0])
	maxSize := msg.maxSize()
	offset := 0

	for {
		oldS := s
		err := msg.unmarshal(&s)

		// Success? Call f and continue
		if err == nil {
			if err := f(offset, msg); err != nil {
				return err
			}
			offset += len(oldS) - len(s)
			continue
		}

		if err != ErrTruncated {
			return err
		}

		// Did we have sucecss in the last iteration?
		if cap(oldS) != cap(buf) {
			// Yes, we need to move the remaining data to the front.
			copy(buf[:len(oldS)], oldS)
		} else {
			// No. We grow the buffer. No need to move the remaining data:
			// it's still in front.
			if len(buf) > maxSize {
				// This shouldn't be possible, but let's error gracefully.
				return errors.New("Unexpected ErrTruncated")
			}

			buf = append(buf, make([]byte, len(buf))...)
		}

		n, err := r.Read(buf[len(oldS):])
		if n == 0 && err == io.EOF {
			break
		}
		if n == 0 {
			return err
		}
		s = cryptobyte.String(buf[:len(oldS)+n])
	}
	return nil
}

func copyUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	var ss cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&ss) {
		return false
	}
	*out = make([]byte, len(ss))
	copy(*out, ss)
	return true
}

func copyUint16LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	var ss cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&ss) {
		return false
	}
	*out = make([]byte, len(ss))
	copy(*out, ss)
	return true
}
