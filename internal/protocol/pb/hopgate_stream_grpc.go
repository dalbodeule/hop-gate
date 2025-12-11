package pb

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// HopGateTunnelClient is the client API for the HopGateTunnel service.
type HopGateTunnelClient interface {
	// OpenTunnel establishes a long-lived bi-directional stream between
	// a HopGate client and the server. Both HTTP requests and responses
	// are multiplexed as Envelope messages on this stream.
	OpenTunnel(ctx context.Context, opts ...grpc.CallOption) (HopGateTunnel_OpenTunnelClient, error)
}

type hopGateTunnelClient struct {
	cc grpc.ClientConnInterface
}

// NewHopGateTunnelClient creates a new HopGateTunnelClient.
func NewHopGateTunnelClient(cc grpc.ClientConnInterface) HopGateTunnelClient {
	return &hopGateTunnelClient{cc: cc}
}

func (c *hopGateTunnelClient) OpenTunnel(ctx context.Context, opts ...grpc.CallOption) (HopGateTunnel_OpenTunnelClient, error) {
	stream, err := c.cc.NewStream(ctx, &_HopGateTunnel_serviceDesc.Streams[0], "/hopgate.protocol.v1.HopGateTunnel/OpenTunnel", opts...)
	if err != nil {
		return nil, err
	}
	return &hopGateTunnelOpenTunnelClient{ClientStream: stream}, nil
}

// HopGateTunnel_OpenTunnelClient is the client-side stream for OpenTunnel.
type HopGateTunnel_OpenTunnelClient interface {
	Send(*Envelope) error
	Recv() (*Envelope, error)
	grpc.ClientStream
}

type hopGateTunnelOpenTunnelClient struct {
	grpc.ClientStream
}

func (x *hopGateTunnelOpenTunnelClient) Send(m *Envelope) error {
	return x.ClientStream.SendMsg(m)
}

func (x *hopGateTunnelOpenTunnelClient) Recv() (*Envelope, error) {
	m := new(Envelope)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// HopGateTunnelServer is the server API for the HopGateTunnel service.
type HopGateTunnelServer interface {
	// OpenTunnel handles a long-lived bi-directional stream between the server
	// and a HopGate client. Implementations are responsible for reading and
	// writing Envelope messages on the stream.
	OpenTunnel(HopGateTunnel_OpenTunnelServer) error
}

// UnimplementedHopGateTunnelServer can be embedded to have forward compatible implementations.
type UnimplementedHopGateTunnelServer struct{}

// OpenTunnel returns an Unimplemented error by default.
func (UnimplementedHopGateTunnelServer) OpenTunnel(HopGateTunnel_OpenTunnelServer) error {
	return status.Errorf(codes.Unimplemented, "method OpenTunnel not implemented")
}

// RegisterHopGateTunnelServer registers the HopGateTunnel service with the given gRPC server.
func RegisterHopGateTunnelServer(s grpc.ServiceRegistrar, srv HopGateTunnelServer) {
	s.RegisterService(&_HopGateTunnel_serviceDesc, srv)
}

// HopGateTunnel_OpenTunnelServer is the server-side stream for OpenTunnel.
type HopGateTunnel_OpenTunnelServer interface {
	Send(*Envelope) error
	Recv() (*Envelope, error)
	grpc.ServerStream
}

func _HopGateTunnel_OpenTunnel_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(HopGateTunnelServer).OpenTunnel(&hopGateTunnelOpenTunnelServer{ServerStream: stream})
}

type hopGateTunnelOpenTunnelServer struct {
	grpc.ServerStream
}

func (x *hopGateTunnelOpenTunnelServer) Send(m *Envelope) error {
	return x.ServerStream.SendMsg(m)
}

func (x *hopGateTunnelOpenTunnelServer) Recv() (*Envelope, error) {
	m := new(Envelope)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _HopGateTunnel_serviceDesc = grpc.ServiceDesc{
	ServiceName: "hopgate.protocol.v1.HopGateTunnel",
	HandlerType: (*HopGateTunnelServer)(nil),
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "OpenTunnel",
			Handler:       _HopGateTunnel_OpenTunnel_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "internal/protocol/hopgate_stream.proto",
}
