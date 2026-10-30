package shadowsocks_2022

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/wyx2685/XrayR/common/limiter"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/time/rate"
)

type testDialer struct {
	dial func(context.Context) (stat.Connection, error)
}

func (d testDialer) Dial(ctx context.Context, _ net.Destination) (stat.Connection, error) {
	return d.dial(ctx)
}
func (testDialer) DestIpAddress() net.IP                                 { return nil }
func (testDialer) SetOutboundGateway(context.Context, *session.Outbound) {}
func clientConfig(version uint32) *ClientConfig {
	key := make([]byte, 16)
	rand.Read(key)
	return &ClientConfig{Address: net.NewIPOrDomain(net.LocalHostIP), Port: 12345, Method: "2022-blake3-aes-128-gcm", Key: base64.StdEncoding.EncodeToString(key), UdpOverTcp: true, UdpOverTcpVersion: version}
}
func processContext(ctx context.Context, network net.Network) context.Context {
	return session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: net.Destination{Network: network, Address: net.LocalHostIP, Port: 53}}})
}

type echoHandler struct{ version uint32 }

func (h echoHandler) NewConnection(ctx context.Context, c stdnet.Conn, metadata M.Metadata) error {
	defer c.Close()
	expected := uot.RequestDestination(uint8(h.version))
	if metadata.Destination.Fqdn != expected.Fqdn {
		return fmt.Errorf("wrong UoT destination")
	}
	request := uot.Request{}
	if h.version != 1 {
		r, err := uot.ReadRequest(c)
		if err != nil {
			return err
		}
		request = *r
	}
	pc := uot.NewConn(c, request)
	payload := B.NewPacket()
	defer payload.Release()
	destination, err := pc.ReadPacket(payload)
	if err != nil {
		return err
	}
	copy := B.As(bytes.Clone(payload.Bytes()))
	return pc.WritePacket(copy, destination)
}
func (echoHandler) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error {
	return errors.New("unexpected native UDP")
}
func (echoHandler) NewError(context.Context, error) {}

type countingReader struct {
	buf.Reader
	bytes atomic.Int64
}

func (r *countingReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	r.bytes.Add(int64(mb.Len()))
	return mb, err
}
func (r *countingReader) Interrupt() {
	if i, ok := r.Reader.(interface{ Interrupt() }); ok {
		i.Interrupt()
	}
}

type countingWriter struct {
	buf.Writer
	bytes atomic.Int64
	delay time.Duration
}

func (w *countingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	time.Sleep(w.delay)
	w.bytes.Add(int64(mb.Len()))
	return w.Writer.WriteMultiBuffer(mb)
}
func (w *countingWriter) Interrupt() {
	if i, ok := w.Writer.(interface{ Interrupt() }); ok {
		i.Interrupt()
	}
}
func (w *countingWriter) Close() error {
	if c, ok := w.Writer.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// These raw inbound types must never be selected as the packet data path.
type rawPacketTrap struct{ stdnet.Conn }

func (rawPacketTrap) ReadFrom([]byte) (int, stdnet.Addr, error) {
	panic("raw packet read bypassed wrappers")
}
func (rawPacketTrap) WriteTo([]byte, stdnet.Addr) (int, error) {
	panic("raw packet write bypassed wrappers")
}

type singPacketTrap struct{ stdnet.Conn }

func (singPacketTrap) ReadPacket(*B.Buffer) (M.Socksaddr, error) {
	panic("sing packet read bypassed wrappers")
}
func (singPacketTrap) WritePacket(*B.Buffer, M.Socksaddr) error {
	panic("sing packet write bypassed wrappers")
}

func TestUoTAllVersionsEncryptedRoundTripAndWrappers(t *testing.T) {
	for _, version := range []uint32{0, 1, 2} {
		for _, kind := range []string{"nil", "net-packet", "sing-packet"} {
			t.Run(fmt.Sprintf("v%d/%s", version, kind), func(t *testing.T) {
				config := clientConfig(version)
				service, err := shadowaead_2022.NewServiceWithPassword(config.Method, config.Key, 60, echoHandler{version}, nil)
				if err != nil {
					t.Fatal(err)
				}
				outbound, err := NewClient(context.Background(), config)
				if err != nil {
					t.Fatal(err)
				}
				client, server := stdnet.Pipe()
				serverDone := make(chan error, 1)
				go func() { serverDone <- service.NewConnection(context.Background(), server, M.Metadata{}) }()
				upR, upW := pipe.New()
				downR, downW := pipe.New()
				cr := &countingReader{Reader: upR}
				cw := &countingWriter{Writer: downW}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				ctx = processContext(ctx, net.Network_UDP)
				switch kind {
				case "net-packet":
					ctx = session.ContextWithInbound(ctx, &session.Inbound{Conn: rawPacketTrap{}})
				case "sing-packet":
					ctx = session.ContextWithInbound(ctx, &session.Inbound{Conn: singPacketTrap{}})
				}
				done := make(chan error, 1)
				rateWriter := limiter.New().RateWriterContext(ctx, cw, rate.NewLimiter(500, 1))
				go func() {
					done <- outbound.Process(ctx, &transport.Link{Reader: cr, Writer: rateWriter}, testDialer{func(context.Context) (stat.Connection, error) { return client, nil }})
				}()
				payload := []byte("encrypted SS2022 UoT packet")
				packet := buf.New()
				packet.Write(payload)
				start := time.Now()
				if err = upW.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
					t.Fatal(err)
				}
				mb, err := downR.ReadMultiBufferTimeout(2 * time.Second)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(mb[0].Bytes(), payload) {
					t.Fatal("payload changed")
				}
				buf.ReleaseMulti(mb)
				if cr.bytes.Load() != int64(len(payload)) || cw.bytes.Load() != int64(len(payload)) || time.Since(start) < 20*time.Millisecond {
					t.Fatal("statistics/rate wrapper bypassed")
				}
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("process did not terminate")
				}
				if err = <-serverDone; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

type failureConn struct {
	stdnet.Conn
	closed atomic.Int32
	err    error
	done   chan struct{}
}

func (c *failureConn) Write([]byte) (int, error) { return 0, c.err }
func (c *failureConn) Read([]byte) (int, error) {
	if c.done != nil {
		<-c.done
	}
	return 0, io.EOF
}
func (c *failureConn) Close() error {
	if c.closed.Add(1) == 1 && c.done != nil {
		close(c.done)
	}
	return nil
}

type errorReader struct{ err error }

func (r errorReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, r.err }
func (r errorReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	return nil, r.err
}

type payloadReader struct{ errorReader }

func (r payloadReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return r.ReadMultiBufferTimeout(0) }

func (r payloadReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	p := buf.New()
	p.WriteString("first payload")
	return buf.MultiBuffer{p}, nil
}

func TestFailuresCloseDialedConnections(t *testing.T) {
	for _, kind := range []string{"payload-eof", "first-write", "handshake", "uot-first-write", "cancel", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			c := &failureConn{err: errors.New("injected first write failure"), done: make(chan struct{})}
			config := clientConfig(2)
			outbound, err := NewClient(context.Background(), config)
			if err != nil {
				t.Fatal(err)
			}
			network := net.Network_TCP
			var reader buf.Reader = errorReader{buf.ErrReadTimeout}
			if kind == "payload-eof" {
				reader = errorReader{io.EOF}
			}
			if kind == "first-write" {
				reader = payloadReader{}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			if kind == "uot-first-write" {
				network = net.Network_UDP
				reader = payloadReader{}
			}
			if kind == "cancel" || kind == "timeout" {
				a, b := stdnet.Pipe()
				defer b.Close()
				upR, _ := pipe.New()
				reader = upR
				if kind == "cancel" {
					cancel()
				}
				err = outbound.Process(processContext(ctx, net.Network_UDP), &transport.Link{Reader: reader, Writer: buf.Discard}, testDialer{func(context.Context) (stat.Connection, error) { return a, nil }})
				if err == nil {
					t.Fatal("cancellation accepted as success")
				}
			} else {
				err = outbound.Process(processContext(ctx, network), &transport.Link{Reader: reader, Writer: buf.Discard}, testDialer{func(context.Context) (stat.Connection, error) { return c, nil }})
				if err == nil || c.closed.Load() == 0 {
					t.Fatal("failure did not close", err, c.closed.Load())
				}
			}
		})
	}
}
func TestInvalidUoTVersions(t *testing.T) {
	for _, v := range []uint32{3, 255, 256, 0xffffffff} {
		if _, err := NewClient(context.Background(), clientConfig(v)); err == nil {
			t.Fatal("invalid version accepted", v)
		}
	}
}

type udpEchoHandler struct{ echoHandler }

type tcpEchoHandler struct{ echoHandler }

func (tcpEchoHandler) NewConnection(ctx context.Context, c stdnet.Conn, _ M.Metadata) error {
	defer c.Close()
	_, err := io.Copy(c, c)
	return err
}
func TestTCPProcessEncryptedPayload(t *testing.T) {
	config := clientConfig(0)
	service, err := shadowaead_2022.NewServiceWithPassword(config.Method, config.Key, 60, tcpEchoHandler{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewClient(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	a, b := stdnet.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- service.NewConnection(context.Background(), b, M.Metadata{}) }()
	upR, upW := pipe.New()
	downR, downW := pipe.New()
	packet := buf.New()
	packet.WriteString("TCP encrypted payload")
	upW.WriteMultiBuffer(buf.MultiBuffer{packet})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- o.Process(processContext(ctx, net.Network_TCP), &transport.Link{Reader: upR, Writer: downW}, testDialer{func(context.Context) (stat.Connection, error) { return a, nil }})
	}()
	mb, err := downR.ReadMultiBufferTimeout(time.Second)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if string(mb[0].Bytes()) != "TCP encrypted payload" {
		t.Fatal("TCP payload mismatch")
	}
	buf.ReleaseMulti(mb)
	upW.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("EOF did not release copy workers")
	}
	<-serverDone
}

func (udpEchoHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, _ M.Metadata) error {
	defer conn.Close()
	packet := B.NewPacket()
	defer packet.Release()
	dest, err := conn.ReadPacket(packet)
	if err != nil {
		return err
	}
	response := B.NewSize(4096)
	response.Resize(1024, 0)
	response.Reserve(32)
	response.Write(packet.Bytes())
	return conn.WritePacket(response, dest)
}
func TestNativeUDPKeepsLinkWrappers(t *testing.T) {
	for _, rawInbound := range []stdnet.Conn{nil, rawPacketTrap{}, singPacketTrap{}} {
		config := clientConfig(0)
		config.UdpOverTcp = false
		service, err := shadowaead_2022.NewServiceWithPassword(config.Method, config.Key, 60, udpEchoHandler{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		server, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		client, err := stdnet.DialUDP("udp", nil, server.LocalAddr().(*stdnet.UDPAddr))
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		serverDone := make(chan error, 1)
		go func() {
			packet := B.NewPacket()
			_, addr, err := packet.ReadPacketFrom(server)
			if err == nil {
				err = service.NewPacket(context.Background(), bufio.NewPacketConn(server), packet, M.Metadata{Source: M.SocksaddrFromNet(addr)})
			} else {
				packet.Release()
			}
			serverDone <- err
		}()
		o, err := NewClient(context.Background(), config)
		if err != nil {
			t.Fatal(err)
		}
		upR, upW := pipe.New()
		downR, downW := pipe.New()
		cr := &countingReader{Reader: upR}
		cw := &countingWriter{Writer: downW}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		ctx = session.ContextWithInbound(processContext(ctx, net.Network_UDP), &session.Inbound{Conn: rawInbound})
		done := make(chan error, 1)
		rateWriter := limiter.New().RateWriterContext(ctx, cw, rate.NewLimiter(500, 1))
		go func() {
			done <- o.Process(ctx, &transport.Link{Reader: cr, Writer: rateWriter}, testDialer{func(context.Context) (stat.Connection, error) { return client, nil }})
		}()
		payload := []byte("native UDP wrapped payload")
		packet := buf.New()
		packet.Write(payload)
		if err = upW.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
			t.Fatal(err)
		}
		mb, err := downR.ReadMultiBufferTimeout(time.Second)
		cancel()
		server.Close()
		<-done
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(mb[0].Bytes(), payload) || cr.bytes.Load() != int64(len(payload)) || cw.bytes.Load() != int64(len(payload)) {
			t.Fatal("native UDP wrapper bypass")
		}
		buf.ReleaseMulti(mb)
		if err = <-serverDone; err != nil {
			t.Fatal(err)
		}
	}
}
func TestRepeatedUoTCancellationNoGoroutineLeak(t *testing.T) {
	baseline := runtime.NumGoroutine()
	o, err := NewClient(context.Background(), clientConfig(2))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		a, b := stdnet.Pipe()
		up, _ := pipe.New()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		o.Process(processContext(ctx, net.Network_UDP), &transport.Link{Reader: up, Writer: buf.Discard}, testDialer{func(context.Context) (stat.Connection, error) { return a, nil }})
		b.Close()
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > baseline+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseline+2 {
		t.Fatalf("goroutines before=%d after=%d", baseline, n)
	}
}
