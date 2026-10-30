package shadowsocks_2022

import (
	"context"
	"time"

	shadowsocks "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

type Outbound struct {
	ctx       context.Context
	server    net.Destination
	method    shadowsocks.Method
	uotClient *uot.Client
}

func NewClient(ctx context.Context, config *ClientConfig) (*Outbound, error) {
	if config.UdpOverTcpVersion > 2 {
		return nil, errors.New("uotVersion must be 0, 1 or 2")
	}
	if config.Address == nil || config.Port == 0 || config.Port > 65535 {
		return nil, errors.New("invalid SS2022 server address/port")
	}
	o := &Outbound{
		ctx: ctx,
		server: net.Destination{
			Address: config.Address.AsAddress(),
			Port:    net.Port(config.Port),
			Network: net.Network_TCP,
		},
	}
	if C.Contains(shadowaead_2022.List, config.Method) {
		if config.Key == "" {
			return nil, errors.New("missing psk")
		}
		method, err := shadowaead_2022.NewWithPassword(config.Method, config.Key, nil)
		if err != nil {
			return nil, errors.New("create method").Base(err)
		}
		o.method = method
	} else {
		return nil, errors.New("unknown method ", config.Method)
	}
	if config.UdpOverTcp {
		o.uotClient = &uot.Client{Version: uint8(config.UdpOverTcpVersion)}
	}
	return o, nil
}

func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	var inboundConn net.Conn
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inboundConn = inbound.Conn
	}

	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 || outbounds[len(outbounds)-1] == nil {
		return errors.New("target not specified")
	}
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "shadowsocks-2022"
	ob.CanSpliceCopy = 3
	destination := ob.Target
	network := destination.Network

	errors.LogInfo(ctx, "tunneling request to ", destination, " via ", o.server.NetAddr())

	serverDestination := o.server
	if o.uotClient != nil {
		serverDestination.Network = net.Network_TCP
	} else {
		serverDestination.Network = network
	}
	connection, err := dialer.Dial(ctx, serverDestination)
	if err != nil {
		return errors.New("failed to connect to server").Base(err)
	}
	defer connection.Close()

	if session.TimeoutOnlyFromContext(ctx) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(context.Background())
		defer cancel()
	}
	// Preserve already delivered downlink buffers on EOF. Interrupting the
	// writer here would discard unread pipe data during normal shutdown.
	shutdown := func() { connection.Close(); common.Interrupt(link.Reader); common.Close(link.Writer) }
	stopCancel := context.AfterFunc(ctx, shutdown)
	defer stopCancel()
	timer := signal.CancelAfterInactivity(ctx, shutdown, 300*time.Second)
	defer timer.SetTimeout(0)

	if network == net.Network_TCP {
		serverConn := o.method.DialEarlyConn(connection, singbridge.ToSocksaddr(destination))
		var handshake bool
		if timeoutReader, isTimeoutReader := link.Reader.(buf.TimeoutReader); isTimeoutReader {
			mb, err := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 100)
			if err != nil && err != buf.ErrNotTimeoutReader && err != buf.ErrReadTimeout {
				buf.ReleaseMulti(mb)
				return errors.New("read payload").Base(err)
			}
			payload := B.New()
			for {
				payload.Reset()
				nb, n := buf.SplitBytes(mb, payload.FreeBytes())
				mb = nb
				if n > 0 {
					payload.Truncate(n)
					_, err = serverConn.Write(payload.Bytes())
					if err != nil {
						payload.Release()
						buf.ReleaseMulti(mb)
						return errors.New("write payload").Base(err)
					}
					handshake = true
				}
				if nb.IsEmpty() {
					break
				}
				mb = nb
			}
			payload.Release()
		}
		if !handshake {
			_, err = serverConn.Write(nil)
			if err != nil {
				return errors.New("client handshake").Base(err)
			}
		}
		pipe := &singbridge.PipeConnWrapper{W: link.Writer, Conn: inboundConn, T: timer, R: &buf.BufferedReader{Reader: link.Reader}}
		return finishCopy(ctx, bufio.CopyConn(ctx, &managedPipe{PipeConnWrapper: pipe, shutdown: shutdown}, serverConn))
	} else {
		// Never use inbound.Conn as a packet data source: it bypasses the
		// dispatcher's statistics and rate-limiting Reader/Writer wrappers.
		packetConn := &linkPacketConn{link: link, dest: destination, timer: timer, shutdown: shutdown}
		defer packetConn.release()

		if o.uotClient != nil {
			uConn, err := o.uotClient.DialEarlyConn(o.method.DialEarlyConn(connection, uot.RequestDestination(o.uotClient.Version)), false, singbridge.ToSocksaddr(destination))
			if err != nil {
				return err
			}
			return finishCopy(ctx, bufio.CopyPacketConn(ctx, packetConn, uConn))
		} else {
			serverConn := o.method.DialPacketConn(connection)
			return finishCopy(ctx, bufio.CopyPacketConn(ctx, packetConn, serverConn))
		}
	}
}

func finishCopy(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Do not normalize a compound copy error just because one of its causes
	// is EOF: that would hide a first-write or handshake failure on the peer.
	return err
}
