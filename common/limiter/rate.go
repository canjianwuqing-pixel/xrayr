package limiter

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type Writer struct {
	writer  buf.Writer
	limiter *rate.Limiter
	ctx     context.Context
}

func (l *Limiter) RateWriter(writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	return l.RateWriterContext(context.Background(), writer, limiter)
}

func (l *Limiter) RateWriterContext(ctx context.Context, writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	return &Writer{
		writer:  writer,
		limiter: limiter,
		ctx:     ctx,
	}
}

func (w *Writer) Close() error {
	return common.Close(w.writer)
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	// WaitN rejects requests larger than Burst. Never ignore that error and
	// forward an unthrottled buffer; reserve the entire payload in bounded chunks.
	for remaining := int(mb.Len()); remaining > 0; {
		n := min(remaining, w.limiter.Burst())
		if n <= 0 {
			buf.ReleaseMulti(mb)
			return io.ErrNoProgress
		}
		if err := w.limiter.WaitN(w.ctx, n); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
		remaining -= n
	}
	return w.writer.WriteMultiBuffer(mb)
}

func (w *Writer) Interrupt() { common.Interrupt(w.writer) }
