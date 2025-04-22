package internal

// Functions to work with the batches' index file into entries and evidence.
//
// The index file consists of 56 byte entries, sorted by key.
//
//   +--------------+--------------+---------------+------------------------+
//   | 32-byte key  | uint64 seqno | uint64 offset | uint64 evidence_offset |
//   +--------------+--------------+---------------+------------------------+
//
// Each entry corresponds to a BatchEntry be. The key is be.Key(),
// the seqno is the sequence number within the entries list,
// the offset is the byte-offset in the entries file, and
// the evidence_offset is the byte-offset in the evidence file.
// offset, evidence_offset, and seqno are encoded big endian.
//
// This allows quick lookups by key using interpolation search.
//
// TODO We can do much better in the number of lookups, and storage space
// required, by using a more complicated index.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/big"
	"slices"

	"github.com/bwesterb/mtc"
	"golang.org/x/exp/mmap"

	"golang.org/x/crypto/cryptobyte"
)

// Handle to an index
type Index struct {
	r *mmap.ReaderAt
}

type IndexSearchResult struct {
	SequenceNumber uint64
	Offset         uint64
	EvidenceOffset uint64
}

type IndexBuildEntry struct {
	Key            [mtc.HashLen]byte
	Offset         uint64
	EvidenceOffset uint64
}

// Opens an index
func OpenIndex(path string) (*Index, error) {
	r, err := mmap.Open(path)
	if err != nil {
		return nil, fmt.Errorf("mmap(%s): %w", path, err)
	}

	if r.Len() == 0 {
		r.Close()
		r = nil
	}

	return &Index{
		r: r,
	}, nil
}

func (h *Index) Close() error {
	if h.r == nil {
		return nil
	}

	return h.r.Close()
}

// Look up hash in the index. If not found, returns nil.
func (h *Index) Search(hash []byte) (*IndexSearchResult, error) {
	const hl = int(mtc.HashLen)
	el := hl + 24 // length of indexEntry

	if len(hash) != hl {
		panic(fmt.Sprintf("hash must be %d bytes", hl))
	}

	if h.r == nil {
		return nil, nil
	}

	// Interpolation search.
	//
	// During the search, we're in an interval [i, j], where
	// the keys of i and j are a and b, and a < hash < b.
	i := 0
	j := (h.r.Len() / el) - 1

	var (
		a      big.Int
		b      big.Int
		needle big.Int

		one     big.Int
		tmp     big.Int
		guess   big.Int
		bMinusA big.Int
		hash2   [hl]byte
	)

	needle.SetBytes(hash)

	// Set b to 0xff...ff.
	one.SetInt64(1)
	b.Lsh(&one, uint(hl)*8)
	b.Sub(&b, &one)

	for {
		// guess = round( (n-a)(j-i)/(b-a) + i ), which we compute
		// as floor ( ((n-a)(j-i) + (b-a)/2) / (b-a) )
		guess.SetInt64(int64(j - i))
		tmp.Sub(&needle, &a)
		tmp.Mul(&tmp, &guess)
		bMinusA.Sub(&b, &a)
		guess.Rsh(&bMinusA, 1)
		guess.Add(&tmp, &guess)
		guess.Div(&guess, &bMinusA)
		intGuess := int(guess.Int64()) + i

		// Fetch value at intGuess
		_, err := h.r.ReadAt(hash2[:], int64(el*intGuess))
		if err != nil {
			return nil, err
		}
		tmp.SetBytes(hash2[:])

		switch tmp.Cmp(&needle) {
		case 0: // we found it
			var (
				val [24]byte
				ret IndexSearchResult
			)
			_, err := h.r.ReadAt(val[:], int64(el*intGuess+hl))
			if err != nil {
				return nil, err
			}
			ss := cryptobyte.String(val[:])
			ss.ReadUint64(&ret.SequenceNumber)
			ss.ReadUint64(&ret.Offset)
			ss.ReadUint64(&ret.EvidenceOffset)
			return &ret, nil
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

type indexEntry struct {
	key            [mtc.HashLen]byte
	seqno          uint64
	offset         uint64
	evidenceOffset uint64
}

type IndexBuilder struct {
	err     error
	w       io.Writer
	seqno   uint64
	entries []indexEntry
}

func NewIndexBuilder(w io.Writer) *IndexBuilder {
	return &IndexBuilder{
		w:       w,
		entries: []indexEntry{},
	}
}

func (ib *IndexBuilder) Push(in IndexBuildEntry) error {
	if ib.err != nil {
		return ib.err
	}

	ib.entries = append(ib.entries, indexEntry{
		seqno:          ib.seqno,
		key:            in.Key,
		offset:         in.Offset,
		evidenceOffset: in.EvidenceOffset,
	})

	ib.seqno++
	return nil
}

func (ib *IndexBuilder) Finish() error {
	// Sort by key
	slices.SortFunc(ib.entries, func(a, ib indexEntry) int {
		return bytes.Compare(a.key[:], ib.key[:])
	})

	// Write out
	bw := bufio.NewWriter(ib.w)
	var lastKey [mtc.HashLen]byte
	for _, entry := range ib.entries {
		if lastKey == entry.key {
			// skip duplicate entries
			continue
		}

		lastKey = entry.key
		var cb cryptobyte.Builder
		cb.AddBytes(entry.key[:])
		cb.AddUint64(entry.seqno)
		cb.AddUint64(entry.offset)
		cb.AddUint64(entry.evidenceOffset)
		buf, _ := cb.Bytes()

		if _, err := bw.Write(buf); err != nil {
			return fmt.Errorf("writing index: %w", err)
		}
	}

	return bw.Flush()
}
