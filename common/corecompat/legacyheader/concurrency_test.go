package legacyheader_test

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/wyx2685/XrayR/common/corecompat/legacyheader"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/srtp"
	dtls "github.com/wyx2685/XrayR/common/corecompat/legacyheader/tls"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/wechat"
)

func TestSharedHeaderConcurrentSerialization(t *testing.T) {
	factories := map[string]func(context.Context, interface{}) (interface{}, error){"srtp": srtp.New, "dtls": dtls.New, "wechat": wechat.NewVideoChat}
	for name, newHeader := range factories {
		t.Run(name, func(t *testing.T) {
			obj, err := newHeader(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			shared := obj.(*legacyheader.Mask).New()
			const workers, perWorker = 32, 100
			frames := make(chan []byte, workers*perWorker)
			var wg sync.WaitGroup
			// Each worker models a distinct connection's packet writer, all sharing
			// the listener header. Locking remains inside Serialize, never socket IO.
			for i := 0; i < workers; i++ {
				wg.Go(func() {
					for j := 0; j < perWorker; j++ {
						b := make([]byte, shared.Size())
						shared.Serialize(b)
						frames <- b
					}
				})
			}
			wg.Wait()
			close(frames)
			seen := make(map[uint32]bool)
			lengths := map[uint32]uint16{}
			for b := range frames {
				var seq uint32
				switch name {
				case "srtp":
					if binary.BigEndian.Uint16(b) != 0xb5e8 {
						t.Fatal("prefix")
					}
					seq = uint32(binary.BigEndian.Uint16(b[2:]))
				case "dtls":
					if b[0] != 23 || b[1] != 254 || b[2] != 253 {
						t.Fatal("prefix")
					}
					seq = binary.BigEndian.Uint32(b[7:])
					lengths[seq] = binary.BigEndian.Uint16(b[11:])
				case "wechat":
					if b[0] != 0xa1 || b[12] != 0x30 {
						t.Fatal("prefix")
					}
					seq = binary.BigEndian.Uint32(b[2:])
				}
				if seen[seq] {
					t.Fatal("duplicate sequence", seq)
				}
				seen[seq] = true
			}
			if len(seen) != workers*perWorker {
				t.Fatal("lost frame")
			}
			if name == "dtls" {
				length := uint16(17)
				for i := 0; i < workers*perWorker; i++ {
					if lengths[uint32(i)] != length {
						t.Fatal("length/sequence mismatch", i)
					}
					length += 17
					if length > 100 {
						length -= 50
					}
				}
			}
		})
	}
}
