// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.21.5
// source: mpcvault/cloudmpc/v1/cloudmpc.proto

package cloudmpc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// CloudMPCServiceClient is the client API for CloudMPCService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CloudMPCServiceClient interface {
	CreateKey(ctx context.Context, in *CreateKeyRequest, opts ...grpc.CallOption) (*CreateKeyResponse, error)
	DescribeKey(ctx context.Context, in *DescribeKeyRequest, opts ...grpc.CallOption) (*DescribeKeyResponse, error)
	Sign(ctx context.Context, in *SignRequest, opts ...grpc.CallOption) (*SignResponse, error)
}

type cloudMPCServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewCloudMPCServiceClient(cc grpc.ClientConnInterface) CloudMPCServiceClient {
	return &cloudMPCServiceClient{cc}
}

func (c *cloudMPCServiceClient) CreateKey(ctx context.Context, in *CreateKeyRequest, opts ...grpc.CallOption) (*CreateKeyResponse, error) {
	out := new(CreateKeyResponse)
	err := c.cc.Invoke(ctx, "/mpcvault.cloudmpc.v1.CloudMPCService/CreateKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cloudMPCServiceClient) DescribeKey(ctx context.Context, in *DescribeKeyRequest, opts ...grpc.CallOption) (*DescribeKeyResponse, error) {
	out := new(DescribeKeyResponse)
	err := c.cc.Invoke(ctx, "/mpcvault.cloudmpc.v1.CloudMPCService/DescribeKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cloudMPCServiceClient) Sign(ctx context.Context, in *SignRequest, opts ...grpc.CallOption) (*SignResponse, error) {
	out := new(SignResponse)
	err := c.cc.Invoke(ctx, "/mpcvault.cloudmpc.v1.CloudMPCService/Sign", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CloudMPCServiceServer is the server API for CloudMPCService service.
// All implementations must embed UnimplementedCloudMPCServiceServer
// for forward compatibility
type CloudMPCServiceServer interface {
	CreateKey(context.Context, *CreateKeyRequest) (*CreateKeyResponse, error)
	DescribeKey(context.Context, *DescribeKeyRequest) (*DescribeKeyResponse, error)
	Sign(context.Context, *SignRequest) (*SignResponse, error)
	mustEmbedUnimplementedCloudMPCServiceServer()
}

// UnimplementedCloudMPCServiceServer must be embedded to have forward compatible implementations.
type UnimplementedCloudMPCServiceServer struct {
}

func (UnimplementedCloudMPCServiceServer) CreateKey(context.Context, *CreateKeyRequest) (*CreateKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateKey not implemented")
}
func (UnimplementedCloudMPCServiceServer) DescribeKey(context.Context, *DescribeKeyRequest) (*DescribeKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DescribeKey not implemented")
}
func (UnimplementedCloudMPCServiceServer) Sign(context.Context, *SignRequest) (*SignResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Sign not implemented")
}
func (UnimplementedCloudMPCServiceServer) mustEmbedUnimplementedCloudMPCServiceServer() {}

// UnsafeCloudMPCServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CloudMPCServiceServer will
// result in compilation errors.
type UnsafeCloudMPCServiceServer interface {
	mustEmbedUnimplementedCloudMPCServiceServer()
}

func RegisterCloudMPCServiceServer(s grpc.ServiceRegistrar, srv CloudMPCServiceServer) {
	s.RegisterService(&CloudMPCService_ServiceDesc, srv)
}

func _CloudMPCService_CreateKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudMPCServiceServer).CreateKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/mpcvault.cloudmpc.v1.CloudMPCService/CreateKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudMPCServiceServer).CreateKey(ctx, req.(*CreateKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CloudMPCService_DescribeKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DescribeKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudMPCServiceServer).DescribeKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/mpcvault.cloudmpc.v1.CloudMPCService/DescribeKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudMPCServiceServer).DescribeKey(ctx, req.(*DescribeKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CloudMPCService_Sign_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudMPCServiceServer).Sign(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/mpcvault.cloudmpc.v1.CloudMPCService/Sign",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudMPCServiceServer).Sign(ctx, req.(*SignRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// CloudMPCService_ServiceDesc is the grpc.ServiceDesc for CloudMPCService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CloudMPCService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "mpcvault.cloudmpc.v1.CloudMPCService",
	HandlerType: (*CloudMPCServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateKey",
			Handler:    _CloudMPCService_CreateKey_Handler,
		},
		{
			MethodName: "DescribeKey",
			Handler:    _CloudMPCService_DescribeKey_Handler,
		},
		{
			MethodName: "Sign",
			Handler:    _CloudMPCService_Sign_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "mpcvault/cloudmpc/v1/cloudmpc.proto",
}
