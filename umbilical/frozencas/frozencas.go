// frozencas implements a simple file format to store small blobs by
// their hash.
//
// The basic format is
//
//	+--------+
//	| header |
//	+--------+
//	| data   |
//	+--------+
//	| index  |
//	+--------+
//
// We put the index after the data so that we write the data first, and
// compute the index afterwards.
//
// The header is given by.
//
//	+---------------------+--------------+
//	| 10-byte "frozencas0"| uint64 count |
//	+---------------------+--------------+
//
// count is the number of blobs. The file ends with the index, which consists
// of count entries, one for each blob, sorted by key.
//
//	+-------------+---------------+---------------+
//	| 32-byte key | uint64 offset | uint24 length |
//	+-------------+---------------+---------------+
//
// key is the SHA-256 hash of the blob (although presently that fact is not
// used); length is the size of the blob in bytes and offset points to
// the blob in the data section.
//
// NOTE There are several improvements that can be made to the format to
// reduce storage requirements and lookup times, but so far we opted for
// something that's simple to implement.
package frozencas

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"slices"

	"golang.org/x/exp/mmap"

	"golang.org/x/crypto/cryptobyte"
)

// Handle to an index
type Handle struct {
	r           *mmap.ReaderAt
	count       uint64
	closed      bool
	indexOffset int64
}

const (
	headerLength     = 10 + 8
	indexEntryLength = 32 + 8 + 3
	magic            = "frozencas0"
)

var (
	ErrClosed   = errors.New("closed")
	ErrFinished = errors.New("finished")
)

func Open(path string) (*Handle, error) {
	r, err := mmap.Open(path)
	if err != nil {
		return nil, fmt.Errorf("mmap(%s): %w", path, err)
	}

	length := r.Len()
	if length < headerLength {
		r.Close()
		return nil, fmt.Errorf("File too short")
	}

	var header [headerLength]byte
	_, err = r.ReadAt(header[:], 0)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}
	if !bytes.Equal(header[:len(magic)], []byte(magic)) {
		return nil, errors.New("Wrong magic")
	}

	var count uint64
	ss := cryptobyte.String(header[len(magic):])
	ss.ReadUint64(&count)

	indexOffset := int64(length) - int64(count)*indexEntryLength

	// No need to keep mmap around if we know it's empty.
	if count == 0 {
		err = r.Close()
		if err != nil {
			return nil, err
		}
		r = nil
	}

	return &Handle{
		r:           r,
		count:       count,
		indexOffset: indexOffset,
	}, nil
}

func (h *Handle) Close() error {
	if h.closed {
		return ErrClosed
	}
	if h.r == nil {
		return nil
	}
	return h.r.Close()
}

func (h *Handle) Entries() ([]IndexEntry, error) {
	ret := make([]IndexEntry, h.count)
	if h.r == nil {
		return ret, nil
	}
	for i := range h.count {
		var buf [indexEntryLength]byte
		_, err := h.r.ReadAt(buf[:], h.indexOffset+indexEntryLength*int64(i))
		if err != nil {
			return nil, err
		}

		copy(ret[i].Key[:], buf[:32])
		ss := cryptobyte.String(buf[32:])
		ss.ReadUint64(&ret[i].Offset)
		ss.ReadUint24(&ret[i].Length)
	}
	return ret, nil
}

// Look up blob by SHA-256 hash in CAS. Returns nil if not present.
//
// Panics if hash is not 32 bytes.
func (h *Handle) Get(hash []byte) ([]byte, error) {
	if h.closed {
		return nil, ErrClosed
	}

	if len(hash) != 32 {
		panic("hash must be 32 bytes")
	}

	if h.r == nil {
		return nil, nil
	}

	// Interpolation search.
	//
	// During the search, we're in an interval [i, j], where
	// the keys of i and j are a and b, and a < hash < b.
	i := int64(0)
	j := int64(h.count) - 1

	var (
		a      big.Int
		b      big.Int
		needle big.Int

		one     big.Int
		tmp     big.Int
		guess   big.Int
		bMinusA big.Int
		hash2   [32]byte
	)

	needle.SetBytes(hash)

	// Set b to 0xff...ff.
	one.SetInt64(1)
	b.Lsh(&one, 32*8)
	b.Sub(&b, &one)

	for {
		// guess = round( (n-a)(j-i)/(b-a) + i ), which we compute
		// as floor ( ((n-a)(j-i) + (b-a)/2) / (b-a) )
		guess.SetInt64(j - i)
		tmp.Sub(&needle, &a)
		tmp.Mul(&tmp, &guess)
		bMinusA.Sub(&b, &a)
		guess.Rsh(&bMinusA, 1)
		guess.Add(&tmp, &guess)
		guess.Div(&guess, &bMinusA)
		intGuess := guess.Int64() + i

		// Fetch value at intGuess
		_, err := h.r.ReadAt(hash2[:], h.indexOffset+indexEntryLength*intGuess)
		if err != nil {
			return nil, err
		}
		tmp.SetBytes(hash2[:])

		switch tmp.Cmp(&needle) {
		case 0: // we found it
			var (
				val    [indexEntryLength - 32]byte
				offset uint64
				length uint32
			)
			_, err := h.r.ReadAt(val[:], h.indexOffset+indexEntryLength*intGuess+32)
			if err != nil {
				return nil, err
			}
			ss := cryptobyte.String(val[:])
			ss.ReadUint64(&offset)
			ss.ReadUint24(&length)

			blob := make([]byte, length)
			_, err = h.r.ReadAt(blob, int64(offset))
			if err != nil {
				return nil, err
			}

			// hash2 := sha256.Sum256(blob)
			// if !bytes.Equal(hash2[:], hash) {
			// 	return nil, errors.New("corrupted blob")
			// }

			return blob, nil
		case -1: // tmp < needle
			a.Set(&tmp)
			i = intGuess + 1
		case 1:
			b.Set(&tmp)
			j = intGuess - 1
		}

		if i > j {
			return nil, nil
		}
	}
}

type IndexEntry struct {
	Key    [32]byte
	Offset uint64
	Length uint32
}

type Builder struct {
	w        io.WriteSeeker
	bw       *bufio.Writer
	entries  []IndexEntry
	keys     map[[32]byte]struct{}
	h        hash.Hash
	offset   uint64
	finished bool
	count    uint64
}

// Creates a new Builder used to create a new FrozenCAS.
func NewBuilder(w io.WriteSeeker) (*Builder, error) {
	_, err := w.Seek(headerLength, io.SeekStart)
	if err != nil {
		return nil, err
	}

	return &Builder{
		w:      w,
		bw:     bufio.NewWriter(w),
		h:      sha256.New(),
		offset: headerLength,
		keys:   make(map[[32]byte]struct{}),
	}, nil
}

func (b *Builder) Add(blob []byte) error {
	var key [32]byte

	if b.finished {
		return ErrFinished
	}

	if len(blob) >= (1 << 24) {
		return errors.New("blob too large")
	}

	_, _ = b.h.Write(blob)
	b.h.Sum(key[:0])
	b.h.Reset()

	if _, ok := b.keys[key]; ok {
		return nil
	}

	_, err := b.bw.Write(blob)
	if err != nil {
		return err
	}

	b.entries = append(b.entries, IndexEntry{
		Key:    key,
		Offset: b.offset,
		Length: uint32(len(blob)),
	})
	b.keys[key] = struct{}{}

	b.offset += uint64(len(blob))
	b.count++
	return nil
}

func (b *Builder) Finish() error {
	if b.finished {
		return ErrFinished
	}
	b.finished = true
	b.keys = nil

	// Sort by key
	slices.SortFunc(b.entries, func(a, b IndexEntry) int {
		return bytes.Compare(a.Key[:], b.Key[:])
	})

	// Write out
	for _, entry := range b.entries {
		var cbb cryptobyte.Builder
		cbb.AddBytes(entry.Key[:])
		cbb.AddUint64(entry.Offset)
		cbb.AddUint24(entry.Length)
		buf, _ := cbb.Bytes()

		_, err := b.bw.Write(buf)
		if err != nil {
			return err
		}
	}

	err := b.bw.Flush()
	if err != nil {
		return err
	}

	_, err = b.w.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	var cbb cryptobyte.Builder
	cbb.AddBytes([]byte(magic))
	cbb.AddUint64(b.count)
	buf, _ := cbb.Bytes()

	_, err = b.w.Write(buf)
	if err != nil {
		return err
	}

	return nil
}
