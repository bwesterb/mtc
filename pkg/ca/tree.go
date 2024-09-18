package ca

import (
	"bytes"
	"fmt"

	"github.com/bwesterb/mtc/pkg/mtc"
	"golang.org/x/exp/mmap"

	"golang.org/x/crypto/cryptobyte"
)

// TreeHandle is a handle to a batches tree file.
// In contrast to mtc.Tree, this doesn't load the whole tree in memory.
type TreeHandle struct {
	r       *mmap.ReaderAt
	nLeaves uint64
}

// OpenTree opens an index
func OpenTree(path string) (*TreeHandle, error) {
	var nLeaves uint64

	r, err := mmap.Open(path)
	if err != nil {
		return nil, fmt.Errorf("mmap(%s): %w", path, err)
	}

	var buf [8]byte
	_, err = r.ReadAt(buf[:], 0)
	if err != nil {
		return nil, err
	}

	s := cryptobyte.String(buf[:])
	s.ReadUint64(&nLeaves)

	nNodes := mtc.TreeNodeCount(nLeaves)

	if r.Len() != int(nNodes*mtc.HashLen+8) {
		return nil, fmt.Errorf("%s: incorrect filesize", path)
	}

	return &TreeHandle{
		r:       r,
		nLeaves: nLeaves,
	}, nil
}

func (t *TreeHandle) Close() error {
	return t.r.Close()
}

// AuthenticationPath returns an authentication path proving that the leaf at the given index
// is included in the Merkle tree.
func (t *TreeHandle) AuthenticationPath(index uint64) ([]byte, error) {
	if index >= t.nLeaves {
		return nil, fmt.Errorf("tree index out of range %d", index)
	}

	var buf [mtc.HashLen]byte
	ret := bytes.Buffer{}
	offset := 8 // Skip nLeaves header
	nNodes := t.nLeaves
	for nNodes != 1 {
		index ^= 1 // index of sibling
		start := offset + int(mtc.HashLen*index)

		_, err := t.r.ReadAt(buf[:], int64(start))
		if err != nil {
			return nil, err
		}
		_, _ = ret.Write(buf[:])

		// Account for the empty node
		if nNodes&1 == 1 {
			nNodes++
		}

		offset += mtc.HashLen * int(nNodes)
		index >>= 1
		nNodes >>= 1
	}

	return ret.Bytes(), nil
}
