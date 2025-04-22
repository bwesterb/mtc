package mtc

import (
	"golang.org/x/crypto/cryptobyte"

	"errors"
	"io"
	"reflect"
)

// Pull-style iterator similar to io.ReadCloser but for general T and
// only pulls one value at a time. Assumes T is a reference.
type Cursor[T any] interface {
	// Pull one value and write to out.
	Pull(out T) error

	// Release underlying resources. Closing twice is no-op.
	Close() error
}

// Pull from c and call f on each.
//
// Abort early if f returns an error. Closes c.
func ForEach[T any](c Cursor[T], f func(T) error) error {
	var t T
	defer c.Close()

	// T is a pointer type, so by default nil. We need to allocate t
	// first. The obvious t = new(T) is wrong, as new(T) is of type *T
	// instead of T. The following does what we want.
	reflect.ValueOf(&t).Elem().Set(reflect.New(reflect.TypeOf(t).Elem()))

	for {
		err := c.Pull(t)
		if err == EOF {
			return nil
		}

		if err != nil {
			return err
		}

		err = f(t)
		if err != nil {
			return err
		}
	}

	panic("shouldn't reach")
}

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

	// Used to indicate end of stream for Cursor[T].
	EOF = errors.New("EOF")
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

// If an object (that implements unmarshaler) implements this
// interface, when unmarshalling a list of  objects, we'll call the
// recordOffset() function with the offset of the object in the list.
//
// This allows us to implement both UnmarshalBatchEntries() and
// UnmarshalBatchEntriesWithOffsets() without too much hassle.
// The latter is required to create an index into the entries file.
type offsetRecorder interface {
	recordOffset(offset int)
}

// Unmarshals a single T from r.
func unmarshalOne[T unmarshaler](r io.Reader) (T, error) {
	c := unmarshal[T](r)
	defer c.Close()
	var t T

	// T is a pointer type, so by default nil. We need to allocate t
	// first. The obvious t = new(T) is wrong, as new(T) is of type *T
	// instead of T. The following does what we want.
	reflect.ValueOf(&t).Elem().Set(reflect.New(reflect.TypeOf(t).Elem()))

	err := c.Pull(t)
	return t, err
}

type streamingUnmarshaler[T unmarshaler] struct {
	r            io.Reader
	buf          []byte
	s            cryptobyte.String
	maxSize      int
	err          error
	offset       int
	recordOffset bool
}

// Unmarshals a stream of T from r.
func unmarshal[T unmarshaler](r io.Reader) Cursor[T] {
	var dummy T
	buf := make([]byte, 512)
	_, recordOffset := any(dummy).(offsetRecorder)
	return &streamingUnmarshaler[T]{
		r:            r,
		buf:          buf,
		s:            cryptobyte.String(buf[:0]),
		maxSize:      dummy.maxSize(),
		recordOffset: recordOffset,
	}
}

func (c *streamingUnmarshaler[T]) Close() error {
	return nil
}

func (c *streamingUnmarshaler[T]) pull(out T) error {
	for {
		oldS := c.s
		err := out.unmarshal(&c.s)

		if err == nil {
			if c.recordOffset {
				any(out).(offsetRecorder).recordOffset(c.offset)
			}

			c.offset += len(oldS) - len(c.s)
			return nil
		}

		if err != ErrTruncated {
			return err
		}

		// Ok, we need to extend the buffer.
		// Did we have success in the last iteration?
		if cap(oldS) != cap(c.buf) {
			// Yes, we need to move the remaining data to the front.
			copy(c.buf[:len(oldS)], oldS)
		} else {
			// No. We grow the buffer. No need to move the remaining data:
			// it's still in front.
			if len(c.buf) > c.maxSize {
				// This shouldn't be possible, but let's error gracefully.
				return errors.New("Unexpected ErrTruncated")
			}

			c.buf = append(c.buf, make([]byte, len(c.buf))...)
		}

		n, err := c.r.Read(c.buf[len(oldS):])
		if n == 0 && err == io.EOF {
			return EOF
		}
		if n == 0 {
			return err
		}
		c.s = cryptobyte.String(c.buf[:len(oldS)+n])
	}

	panic("shouldn't reach")
}

func (c *streamingUnmarshaler[T]) Pull(out T) error {
	if c.err != nil {
		return c.err
	}

	err := c.pull(out)

	if err != nil {
		c.err = err
	}

	return err
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
