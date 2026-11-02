package shadowsocks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

// Exercise real authentication and account-local replay checking before dispatch.
var replayPayload = bytes.Repeat([]byte("authenticated uplink payload;"), 8)

type replayScenario struct {
	name                            string
	duplicate, unknown, withHistory bool
	want                            error
}

var replayScenarios = []replayScenario{
	{name: "authorized"},
	{name: "duplicate_iv", duplicate: true, want: ErrIVNotUnique},
	{name: "unknown_credential", unknown: true, want: ErrNotFound},
	{name: "existing_history", withHistory: true},
}

func replayFixture(t *testing.T, scenario replayScenario, udp bool) (*Validator, []byte, *protocol.MemoryUser) {
	t.Helper()
	account, err := (&Account{Password: ephemeralPassword(), CipherType: CipherType_AES_128_GCM, IvCheck: true}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	serverAccount := account.(*MemoryAccount)
	validator := new(Validator)
	user := &protocol.MemoryUser{Email: "compat-regression@example.invalid", Account: serverAccount}
	if err = validator.Add(user); err != nil {
		t.Fatal(err)
	}
	serverAccount = validator.GetByEmail(user.Email).Account.(*MemoryAccount)
	// A distinct client account avoids registering locally generated salts in the
	// server store before they cross the actual protocol authentication boundary.
	clientRaw := &Account{Password: serverAccount.Password, CipherType: serverAccount.CipherType}
	if scenario.unknown {
		clientRaw.Password = ephemeralPassword()
	}
	clientAccount, err := clientRaw.AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	client := &protocol.MemoryUser{Email: user.Email, Account: clientAccount}
	request := &protocol.RequestHeader{Version: Version, User: client, Command: protocol.RequestCommandTCP, Address: xnet.LocalHostIP, Port: 12345}
	var wire []byte
	if udp {
		request.Command = protocol.RequestCommandUDP
		packet, err := EncodeUDPPacket(request, replayPayload)
		if err != nil {
			t.Fatal(err)
		}
		wire = bytes.Clone(packet.Bytes())
		packet.Release()
	} else {
		var encoded bytes.Buffer
		writer, err := WriteTCPRequest(request, &encoded)
		if err != nil {
			t.Fatal(err)
		}
		if err = writer.WriteMultiBuffer(buf.MergeBytes(nil, replayPayload)); err != nil {
			t.Fatal(err)
		}
		wire = bytes.Clone(encoded.Bytes())
	}
	if scenario.withHistory {
		salt := bytes.Repeat([]byte{0xa5}, 16)
		if bytes.Equal(salt, wire[:16]) {
			t.Fatal("fixture salt collision")
		}
		if err = serverAccount.CheckIV(salt); err != nil {
			t.Fatal(err)
		}
	}
	if scenario.duplicate {
		if err = serverAccount.CheckIV(wire[:16]); err != nil {
			t.Fatal(err)
		}
	}
	return validator, wire, client
}

func TestReadTCPSessionAuthentication(t *testing.T) {
	for _, scenario := range replayScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			v, wire, _ := replayFixture(t, scenario, false)
			attempts := 1
			if scenario.want != nil {
				attempts = 3
			}
			for attempt := 0; attempt < attempts; attempt++ {
				request, reader, err := ReadTCPSession(v, bytes.NewReader(wire))
				if scenario.want != nil {
					if !errors.Is(err, scenario.want) || request != nil || reader != nil {
						t.Fatalf("attempt %d: error=%v, request=%v, reader=%T; want %v and no request", attempt, err, request, reader, scenario.want)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if request.Address.String() != "127.0.0.1" || request.Port != 12345 || request.User.Email != "compat-regression@example.invalid" {
					t.Fatal("decoded request mismatch")
				}
				var body bytes.Buffer
				if err = buf.Copy(reader, buf.NewWriter(&body)); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(body.Bytes(), replayPayload) {
					t.Fatal("authorized payload changed")
				}
			}
		})
	}
}

type replayPolicy struct{ policy.Manager }

func (replayPolicy) ForLevel(uint32) policy.Session {
	p := policy.SessionDefault()
	p.Timeouts.Handshake = 2 * time.Second
	return p
}

type replayDispatcher struct {
	routing.Dispatcher
	listener                     net.Listener
	mu                           sync.Mutex
	connections                  []net.Conn
	workers                      sync.WaitGroup
	dispatches, dials, forwarded atomic.Int64
}

func newReplayDispatcher(t *testing.T) *replayDispatcher {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &replayDispatcher{listener: listener}
	acceptDone := make(chan struct{})
	d.workers.Go(func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			d.mu.Lock()
			d.connections = append(d.connections, conn)
			d.mu.Unlock()
			d.workers.Go(func() { defer conn.Close(); io.Copy(conn, conn) })
		}
	})
	t.Cleanup(func() {
		listener.Close()
		<-acceptDone // No accepted connection can be registered after cleanup snapshots the list.
		d.mu.Lock()
		for _, conn := range d.connections {
			conn.Close()
		}
		d.mu.Unlock()
		d.workers.Wait()
	})
	return d
}

type replayForwardWriter struct {
	conn  *net.TCPConn
	bytes *atomic.Int64
}

func (w *replayForwardWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		p := b.Bytes()
		for len(p) > 0 {
			n, err := w.conn.Write(p)
			w.bytes.Add(int64(n))
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrNoProgress
			}
			p = p[n:]
		}
	}
	return nil
}
func (w *replayForwardWriter) Close() error { return w.conn.CloseWrite() }
func (w *replayForwardWriter) Interrupt()   { w.conn.Close() }

func (d *replayDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	d.dispatches.Add(1)
	if dest.Address.String() != "127.0.0.1" || dest.Port != 12345 {
		return nil, errors.New("wrong dispatched destination")
	}
	d.dials.Add(1)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", d.listener.Addr().String())
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.connections = append(d.connections, conn)
	d.mu.Unlock()
	return &transport.Link{Reader: &buf.SingleReader{Reader: conn}, Writer: &replayForwardWriter{conn: conn.(*net.TCPConn), bytes: &d.forwarded}}, nil
}
func (d *replayDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	d.dispatches.Add(1)
	return errors.New("unexpected DispatchLink")
}

func runReplayTCPProcess(t *testing.T, v *Validator, wire []byte, clientUser *protocol.MemoryUser, dispatcher *replayDispatcher, accepted bool) error {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client.SetDeadline(time.Now().Add(4 * time.Second))
	server.SetDeadline(time.Now().Add(4 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Source: xnet.TCPDestination(xnet.LocalHostIP, 23456)})
	s := &Server{validator: v, policyManager: replayPolicy{}}
	done := make(chan error, 1)
	go func() { defer server.Close(); done <- s.Process(ctx, xnet.Network_TCP, server, dispatcher) }()
	if _, err = client.Write(wire); err != nil {
		t.Fatal(err)
	}
	if err = client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if accepted {
		reader, err := ReadTCPResponse(clientUser, client)
		if err != nil {
			t.Fatal(err)
		}
		var reply bytes.Buffer
		if err = buf.Copy(reader, buf.NewWriter(&reply)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(reply.Bytes(), replayPayload) {
			t.Fatal("actual TCP echo changed")
		}
	}
	select {
	case err = <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Server.Process did not finish")
		return nil
	}
}

func TestServerTCPAuthenticationStopsDispatch(t *testing.T) {
	for _, scenario := range replayScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			v, wire, user := replayFixture(t, scenario, false)
			d := newReplayDispatcher(t)
			attempts := 1
			if scenario.want != nil {
				attempts = 3
			}
			for attempt := 0; attempt < attempts; attempt++ {
				err := runReplayTCPProcess(t, v, wire, user, d, scenario.want == nil)
				if scenario.want != nil {
					if !errors.Is(err, scenario.want) {
						t.Errorf("attempt %d lost rejection cause: %v; want %v", attempt, err, scenario.want)
					}
					if d.dispatches.Load() != 0 || d.dials.Load() != 0 || d.forwarded.Load() != 0 {
						t.Fatalf("rejection reached outbound: dispatch=%d dial=%d uplink=%d", d.dispatches.Load(), d.dials.Load(), d.forwarded.Load())
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if d.dispatches.Load() != 1 || d.dials.Load() != 1 || d.forwarded.Load() != int64(len(replayPayload)) {
						t.Fatal("authorized request never traversed real outbound fixture")
					}
				}
			}
			t.Logf("attempts=%d dispatch=%d dial=%d uplink_bytes=%d", attempts, d.dispatches.Load(), d.dials.Load(), d.forwarded.Load())
		})
	}
}

func TestUDPAuthenticationPropagation(t *testing.T) {
	for _, scenario := range replayScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			v, wire, _ := replayFixture(t, scenario, true)
			packet := buf.New()
			packet.Write(wire)
			defer packet.Release()
			request, payload, err := DecodeUDPPacket(v, packet)
			if scenario.want == nil {
				if err != nil || request == nil || !bytes.Equal(payload.Bytes(), replayPayload) {
					t.Fatalf("UDP decode: %v", err)
				}
				return
			}
			if !errors.Is(err, scenario.want) || request != nil || payload != nil {
				t.Fatalf("UDP lost cause: %v; want %v", err, scenario.want)
			}
			d := newReplayDispatcher(t)
			for attempt := 0; attempt < 3; attempt++ {
				server, client := net.Pipe()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				ctx = session.ContextWithInbound(ctx, &session.Inbound{Source: xnet.UDPDestination(xnet.LocalHostIP, 23456)})
				s := &Server{validator: v}
				done := make(chan error, 1)
				go func() { defer server.Close(); done <- s.Process(ctx, xnet.Network_UDP, server, d) }()
				client.SetWriteDeadline(time.Now().Add(time.Second))
				_, writeErr := client.Write(wire)
				client.Close()
				if writeErr != nil {
					cancel()
					t.Fatal(writeErr)
				}
				select {
				case err = <-done:
				case <-time.After(2 * time.Second):
					server.Close()
					cancel()
					t.Fatal("UDP drop path blocked")
				}
				cancel()
				if err != nil {
					t.Fatal(err)
				} // UDP invalid packets are dropped, not returned as session errors.
			}
			if d.dispatches.Load() != 0 || d.dials.Load() != 0 || d.forwarded.Load() != 0 {
				t.Fatal("UDP rejected packet reached outbound")
			}
			t.Logf("attempts=3 dispatch=%d dial=%d uplink_bytes=%d (controlled packet reader)", d.dispatches.Load(), d.dials.Load(), d.forwarded.Load())
		})
	}
}
