package limiter

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/wyx2685/XrayR/api"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

func TestWriterLargeBufferAndCancellation(t *testing.T) {
	l := New()
	bucket := rate.NewLimiter(1000, 10)
	w := l.RateWriter(buf.Discard, bucket)
	start := time.Now()
	if err := w.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, 40))); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 20*time.Millisecond {
		t.Fatal("large buffer bypassed rate limit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w = l.RateWriterContext(ctx, buf.Discard, rate.NewLimiter(1, 1))
	if err := w.WriteMultiBuffer(buf.MergeBytes(nil, []byte("payload"))); err == nil {
		t.Fatal("cancelled write succeeded")
	}
}

func TestConcurrentUserAndAliveUpdates(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "test@example.invalid", SpeedLimit: 1000000}}
	if err := l.AddInboundLimiter("test", 2000000, &users, nil); err != nil {
		t.Fatal(err)
	}
	v, _ := l.InboundInfo.Load("test")
	i := v.(*InboundInfo)
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if err := l.UpdateInboundLimiter("test", &users); err != nil {
					t.Error(err)
				}
				i.SetAliveList(map[int]int{1: j % 2})
				bucket, ok, reject := l.GetUserBucket("test", "test|test@example.invalid|1", "127.0.0.1", true)
				if bucket == nil || !ok || reject {
					t.Error("unexpected limiter result")
				}
			}
		}()
	}
	wg.Wait()
}
