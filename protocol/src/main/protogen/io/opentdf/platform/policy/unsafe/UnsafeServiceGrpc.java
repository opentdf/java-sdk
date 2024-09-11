package io.opentdf.platform.policy.unsafe;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 * <pre>
 *&#47;
 * / Unsafe Service 
 * / IN FLIGHT AND NOT YET IMPLEMENTED!
 * /
 * </pre>
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.61.1)",
    comments = "Source: policy/unsafe/unsafe.proto")
@io.grpc.stub.annotations.GrpcGenerated
public final class UnsafeServiceGrpc {

  private UnsafeServiceGrpc() {}

  public static final java.lang.String SERVICE_NAME = "policy.unsafe.UnsafeService";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceRequest,
      io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceResponse> getUnsafeUpdateNamespaceMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UnsafeUpdateNamespace",
      requestType = io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceRequest.class,
      responseType = io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceRequest,
      io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceResponse> getUnsafeUpdateNamespaceMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceRequest, io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceResponse> getUnsafeUpdateNamespaceMethod;
    if ((getUnsafeUpdateNamespaceMethod = UnsafeServiceGrpc.getUnsafeUpdateNamespaceMethod) == null) {
      synchronized (UnsafeServiceGrpc.class) {
        if ((getUnsafeUpdateNamespaceMethod = UnsafeServiceGrpc.getUnsafeUpdateNamespaceMethod) == null) {
          UnsafeServiceGrpc.getUnsafeUpdateNamespaceMethod = getUnsafeUpdateNamespaceMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceRequest, io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UnsafeUpdateNamespace"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceResponse.getDefaultInstance()))
              .setSchemaDescriptor(new UnsafeServiceMethodDescriptorSupplier("UnsafeUpdateNamespace"))
              .build();
        }
      }
    }
    return getUnsafeUpdateNamespaceMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceRequest,
      io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceResponse> getUnsafeReactivateNamespaceMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UnsafeReactivateNamespace",
      requestType = io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceRequest.class,
      responseType = io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceRequest,
      io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceResponse> getUnsafeReactivateNamespaceMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceRequest, io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceResponse> getUnsafeReactivateNamespaceMethod;
    if ((getUnsafeReactivateNamespaceMethod = UnsafeServiceGrpc.getUnsafeReactivateNamespaceMethod) == null) {
      synchronized (UnsafeServiceGrpc.class) {
        if ((getUnsafeReactivateNamespaceMethod = UnsafeServiceGrpc.getUnsafeReactivateNamespaceMethod) == null) {
          UnsafeServiceGrpc.getUnsafeReactivateNamespaceMethod = getUnsafeReactivateNamespaceMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceRequest, io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UnsafeReactivateNamespace"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceResponse.getDefaultInstance()))
              .setSchemaDescriptor(new UnsafeServiceMethodDescriptorSupplier("UnsafeReactivateNamespace"))
              .build();
        }
      }
    }
    return getUnsafeReactivateNamespaceMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceRequest,
      io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceResponse> getUnsafeDeleteNamespaceMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UnsafeDeleteNamespace",
      requestType = io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceRequest.class,
      responseType = io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceRequest,
      io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceResponse> getUnsafeDeleteNamespaceMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceRequest, io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceResponse> getUnsafeDeleteNamespaceMethod;
    if ((getUnsafeDeleteNamespaceMethod = UnsafeServiceGrpc.getUnsafeDeleteNamespaceMethod) == null) {
      synchronized (UnsafeServiceGrpc.class) {
        if ((getUnsafeDeleteNamespaceMethod = UnsafeServiceGrpc.getUnsafeDeleteNamespaceMethod) == null) {
          UnsafeServiceGrpc.getUnsafeDeleteNamespaceMethod = getUnsafeDeleteNamespaceMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceRequest, io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UnsafeDeleteNamespace"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceResponse.getDefaultInstance()))
              .setSchemaDescriptor(new UnsafeServiceMethodDescriptorSupplier("UnsafeDeleteNamespace"))
              .build();
        }
      }
    }
    return getUnsafeDeleteNamespaceMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeRequest,
      io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeResponse> getUnsafeUpdateAttributeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UnsafeUpdateAttribute",
      requestType = io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeRequest.class,
      responseType = io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeRequest,
      io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeResponse> getUnsafeUpdateAttributeMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeRequest, io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeResponse> getUnsafeUpdateAttributeMethod;
    if ((getUnsafeUpdateAttributeMethod = UnsafeServiceGrpc.getUnsafeUpdateAttributeMethod) == null) {
      synchronized (UnsafeServiceGrpc.class) {
        if ((getUnsafeUpdateAttributeMethod = UnsafeServiceGrpc.getUnsafeUpdateAttributeMethod) == null) {
          UnsafeServiceGrpc.getUnsafeUpdateAttributeMethod = getUnsafeUpdateAttributeMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeRequest, io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UnsafeUpdateAttribute"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeResponse.getDefaultInstance()))
              .setSchemaDescriptor(new UnsafeServiceMethodDescriptorSupplier("UnsafeUpdateAttribute"))
              .build();
        }
      }
    }
    return getUnsafeUpdateAttributeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeRequest,
      io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeResponse> getUnsafeReactivateAttributeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UnsafeReactivateAttribute",
      requestType = io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeRequest.class,
      responseType = io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeRequest,
      io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeResponse> getUnsafeReactivateAttributeMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeRequest, io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeResponse> getUnsafeReactivateAttributeMethod;
    if ((getUnsafeReactivateAttributeMethod = UnsafeServiceGrpc.getUnsafeReactivateAttributeMethod) == null) {
      synchronized (UnsafeServiceGrpc.class) {
        if ((getUnsafeReactivateAttributeMethod = UnsafeServiceGrpc.getUnsafeReactivateAttributeMethod) == null) {
          UnsafeServiceGrpc.getUnsafeReactivateAttributeMethod = getUnsafeReactivateAttributeMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeRequest, io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UnsafeReactivateAttribute"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeResponse.getDefaultInstance()))
              .setSchemaDescriptor(new UnsafeServiceMethodDescriptorSupplier("UnsafeReactivateAttribute"))
              .build();
        }
      }
    }
    return getUnsafeReactivateAttributeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeRequest,
      io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeResponse> getUnsafeDeleteAttributeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UnsafeDeleteAttribute",
      requestType = io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeRequest.class,
      responseType = io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeRequest,
      io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeResponse> getUnsafeDeleteAttributeMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeRequest, io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeResponse> getUnsafeDeleteAttributeMethod;
    if ((getUnsafeDeleteAttributeMethod = UnsafeServiceGrpc.getUnsafeDeleteAttributeMethod) == null) {
      synchronized (UnsafeServiceGrpc.class) {
        if ((getUnsafeDeleteAttributeMethod = UnsafeServiceGrpc.getUnsafeDeleteAttributeMethod) == null) {
          UnsafeServiceGrpc.getUnsafeDeleteAttributeMethod = getUnsafeDeleteAttributeMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeRequest, io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UnsafeDeleteAttribute"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeResponse.getDefaultInstance()))
              .setSchemaDescriptor(new UnsafeServiceMethodDescriptorSupplier("UnsafeDeleteAttribute"))
              .build();
        }
      }
    }
    return getUnsafeDeleteAttributeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueRequest,
      io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueResponse> getUnsafeUpdateAttributeValueMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UnsafeUpdateAttributeValue",
      requestType = io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueRequest.class,
      responseType = io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueRequest,
      io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueResponse> getUnsafeUpdateAttributeValueMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueRequest, io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueResponse> getUnsafeUpdateAttributeValueMethod;
    if ((getUnsafeUpdateAttributeValueMethod = UnsafeServiceGrpc.getUnsafeUpdateAttributeValueMethod) == null) {
      synchronized (UnsafeServiceGrpc.class) {
        if ((getUnsafeUpdateAttributeValueMethod = UnsafeServiceGrpc.getUnsafeUpdateAttributeValueMethod) == null) {
          UnsafeServiceGrpc.getUnsafeUpdateAttributeValueMethod = getUnsafeUpdateAttributeValueMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueRequest, io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UnsafeUpdateAttributeValue"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueResponse.getDefaultInstance()))
              .setSchemaDescriptor(new UnsafeServiceMethodDescriptorSupplier("UnsafeUpdateAttributeValue"))
              .build();
        }
      }
    }
    return getUnsafeUpdateAttributeValueMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueRequest,
      io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueResponse> getUnsafeReactivateAttributeValueMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UnsafeReactivateAttributeValue",
      requestType = io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueRequest.class,
      responseType = io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueRequest,
      io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueResponse> getUnsafeReactivateAttributeValueMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueRequest, io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueResponse> getUnsafeReactivateAttributeValueMethod;
    if ((getUnsafeReactivateAttributeValueMethod = UnsafeServiceGrpc.getUnsafeReactivateAttributeValueMethod) == null) {
      synchronized (UnsafeServiceGrpc.class) {
        if ((getUnsafeReactivateAttributeValueMethod = UnsafeServiceGrpc.getUnsafeReactivateAttributeValueMethod) == null) {
          UnsafeServiceGrpc.getUnsafeReactivateAttributeValueMethod = getUnsafeReactivateAttributeValueMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueRequest, io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UnsafeReactivateAttributeValue"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueResponse.getDefaultInstance()))
              .setSchemaDescriptor(new UnsafeServiceMethodDescriptorSupplier("UnsafeReactivateAttributeValue"))
              .build();
        }
      }
    }
    return getUnsafeReactivateAttributeValueMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueRequest,
      io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueResponse> getUnsafeDeleteAttributeValueMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UnsafeDeleteAttributeValue",
      requestType = io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueRequest.class,
      responseType = io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueRequest,
      io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueResponse> getUnsafeDeleteAttributeValueMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueRequest, io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueResponse> getUnsafeDeleteAttributeValueMethod;
    if ((getUnsafeDeleteAttributeValueMethod = UnsafeServiceGrpc.getUnsafeDeleteAttributeValueMethod) == null) {
      synchronized (UnsafeServiceGrpc.class) {
        if ((getUnsafeDeleteAttributeValueMethod = UnsafeServiceGrpc.getUnsafeDeleteAttributeValueMethod) == null) {
          UnsafeServiceGrpc.getUnsafeDeleteAttributeValueMethod = getUnsafeDeleteAttributeValueMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueRequest, io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UnsafeDeleteAttributeValue"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueResponse.getDefaultInstance()))
              .setSchemaDescriptor(new UnsafeServiceMethodDescriptorSupplier("UnsafeDeleteAttributeValue"))
              .build();
        }
      }
    }
    return getUnsafeDeleteAttributeValueMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static UnsafeServiceStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<UnsafeServiceStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<UnsafeServiceStub>() {
        @java.lang.Override
        public UnsafeServiceStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new UnsafeServiceStub(channel, callOptions);
        }
      };
    return UnsafeServiceStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static UnsafeServiceBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<UnsafeServiceBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<UnsafeServiceBlockingStub>() {
        @java.lang.Override
        public UnsafeServiceBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new UnsafeServiceBlockingStub(channel, callOptions);
        }
      };
    return UnsafeServiceBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static UnsafeServiceFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<UnsafeServiceFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<UnsafeServiceFutureStub>() {
        @java.lang.Override
        public UnsafeServiceFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new UnsafeServiceFutureStub(channel, callOptions);
        }
      };
    return UnsafeServiceFutureStub.newStub(factory, channel);
  }

  /**
   * <pre>
   *&#47;
   * / Unsafe Service 
   * / IN FLIGHT AND NOT YET IMPLEMENTED!
   * /
   * </pre>
   */
  public interface AsyncService {

    /**
     * <pre>
     *--------------------------------------*
     * Namespace RPCs
     *---------------------------------------
     * </pre>
     */
    default void unsafeUpdateNamespace(io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUnsafeUpdateNamespaceMethod(), responseObserver);
    }

    /**
     */
    default void unsafeReactivateNamespace(io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUnsafeReactivateNamespaceMethod(), responseObserver);
    }

    /**
     */
    default void unsafeDeleteNamespace(io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUnsafeDeleteNamespaceMethod(), responseObserver);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Attribute RPCs
     *---------------------------------------
     * </pre>
     */
    default void unsafeUpdateAttribute(io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUnsafeUpdateAttributeMethod(), responseObserver);
    }

    /**
     */
    default void unsafeReactivateAttribute(io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUnsafeReactivateAttributeMethod(), responseObserver);
    }

    /**
     */
    default void unsafeDeleteAttribute(io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUnsafeDeleteAttributeMethod(), responseObserver);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Value RPCs
     *---------------------------------------
     * </pre>
     */
    default void unsafeUpdateAttributeValue(io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUnsafeUpdateAttributeValueMethod(), responseObserver);
    }

    /**
     */
    default void unsafeReactivateAttributeValue(io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUnsafeReactivateAttributeValueMethod(), responseObserver);
    }

    /**
     */
    default void unsafeDeleteAttributeValue(io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUnsafeDeleteAttributeValueMethod(), responseObserver);
    }
  }

  /**
   * Base class for the server implementation of the service UnsafeService.
   * <pre>
   *&#47;
   * / Unsafe Service 
   * / IN FLIGHT AND NOT YET IMPLEMENTED!
   * /
   * </pre>
   */
  public static abstract class UnsafeServiceImplBase
      implements io.grpc.BindableService, AsyncService {

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return UnsafeServiceGrpc.bindService(this);
    }
  }

  /**
   * A stub to allow clients to do asynchronous rpc calls to service UnsafeService.
   * <pre>
   *&#47;
   * / Unsafe Service 
   * / IN FLIGHT AND NOT YET IMPLEMENTED!
   * /
   * </pre>
   */
  public static final class UnsafeServiceStub
      extends io.grpc.stub.AbstractAsyncStub<UnsafeServiceStub> {
    private UnsafeServiceStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected UnsafeServiceStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new UnsafeServiceStub(channel, callOptions);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Namespace RPCs
     *---------------------------------------
     * </pre>
     */
    public void unsafeUpdateNamespace(io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUnsafeUpdateNamespaceMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void unsafeReactivateNamespace(io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUnsafeReactivateNamespaceMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void unsafeDeleteNamespace(io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUnsafeDeleteNamespaceMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Attribute RPCs
     *---------------------------------------
     * </pre>
     */
    public void unsafeUpdateAttribute(io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUnsafeUpdateAttributeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void unsafeReactivateAttribute(io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUnsafeReactivateAttributeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void unsafeDeleteAttribute(io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUnsafeDeleteAttributeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Value RPCs
     *---------------------------------------
     * </pre>
     */
    public void unsafeUpdateAttributeValue(io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUnsafeUpdateAttributeValueMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void unsafeReactivateAttributeValue(io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUnsafeReactivateAttributeValueMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void unsafeDeleteAttributeValue(io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUnsafeDeleteAttributeValueMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   * A stub to allow clients to do synchronous rpc calls to service UnsafeService.
   * <pre>
   *&#47;
   * / Unsafe Service 
   * / IN FLIGHT AND NOT YET IMPLEMENTED!
   * /
   * </pre>
   */
  public static final class UnsafeServiceBlockingStub
      extends io.grpc.stub.AbstractBlockingStub<UnsafeServiceBlockingStub> {
    private UnsafeServiceBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected UnsafeServiceBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new UnsafeServiceBlockingStub(channel, callOptions);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Namespace RPCs
     *---------------------------------------
     * </pre>
     */
    public io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceResponse unsafeUpdateNamespace(io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUnsafeUpdateNamespaceMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceResponse unsafeReactivateNamespace(io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUnsafeReactivateNamespaceMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceResponse unsafeDeleteNamespace(io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUnsafeDeleteNamespaceMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Attribute RPCs
     *---------------------------------------
     * </pre>
     */
    public io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeResponse unsafeUpdateAttribute(io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUnsafeUpdateAttributeMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeResponse unsafeReactivateAttribute(io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUnsafeReactivateAttributeMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeResponse unsafeDeleteAttribute(io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUnsafeDeleteAttributeMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Value RPCs
     *---------------------------------------
     * </pre>
     */
    public io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueResponse unsafeUpdateAttributeValue(io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUnsafeUpdateAttributeValueMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueResponse unsafeReactivateAttributeValue(io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUnsafeReactivateAttributeValueMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueResponse unsafeDeleteAttributeValue(io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUnsafeDeleteAttributeValueMethod(), getCallOptions(), request);
    }
  }

  /**
   * A stub to allow clients to do ListenableFuture-style rpc calls to service UnsafeService.
   * <pre>
   *&#47;
   * / Unsafe Service 
   * / IN FLIGHT AND NOT YET IMPLEMENTED!
   * /
   * </pre>
   */
  public static final class UnsafeServiceFutureStub
      extends io.grpc.stub.AbstractFutureStub<UnsafeServiceFutureStub> {
    private UnsafeServiceFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected UnsafeServiceFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new UnsafeServiceFutureStub(channel, callOptions);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Namespace RPCs
     *---------------------------------------
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceResponse> unsafeUpdateNamespace(
        io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUnsafeUpdateNamespaceMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceResponse> unsafeReactivateNamespace(
        io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUnsafeReactivateNamespaceMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceResponse> unsafeDeleteNamespace(
        io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUnsafeDeleteNamespaceMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Attribute RPCs
     *---------------------------------------
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeResponse> unsafeUpdateAttribute(
        io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUnsafeUpdateAttributeMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeResponse> unsafeReactivateAttribute(
        io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUnsafeReactivateAttributeMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeResponse> unsafeDeleteAttribute(
        io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUnsafeDeleteAttributeMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Value RPCs
     *---------------------------------------
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueResponse> unsafeUpdateAttributeValue(
        io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUnsafeUpdateAttributeValueMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueResponse> unsafeReactivateAttributeValue(
        io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUnsafeReactivateAttributeValueMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueResponse> unsafeDeleteAttributeValue(
        io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUnsafeDeleteAttributeValueMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_UNSAFE_UPDATE_NAMESPACE = 0;
  private static final int METHODID_UNSAFE_REACTIVATE_NAMESPACE = 1;
  private static final int METHODID_UNSAFE_DELETE_NAMESPACE = 2;
  private static final int METHODID_UNSAFE_UPDATE_ATTRIBUTE = 3;
  private static final int METHODID_UNSAFE_REACTIVATE_ATTRIBUTE = 4;
  private static final int METHODID_UNSAFE_DELETE_ATTRIBUTE = 5;
  private static final int METHODID_UNSAFE_UPDATE_ATTRIBUTE_VALUE = 6;
  private static final int METHODID_UNSAFE_REACTIVATE_ATTRIBUTE_VALUE = 7;
  private static final int METHODID_UNSAFE_DELETE_ATTRIBUTE_VALUE = 8;

  private static final class MethodHandlers<Req, Resp> implements
      io.grpc.stub.ServerCalls.UnaryMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ServerStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ClientStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.BidiStreamingMethod<Req, Resp> {
    private final AsyncService serviceImpl;
    private final int methodId;

    MethodHandlers(AsyncService serviceImpl, int methodId) {
      this.serviceImpl = serviceImpl;
      this.methodId = methodId;
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public void invoke(Req request, io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        case METHODID_UNSAFE_UPDATE_NAMESPACE:
          serviceImpl.unsafeUpdateNamespace((io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceResponse>) responseObserver);
          break;
        case METHODID_UNSAFE_REACTIVATE_NAMESPACE:
          serviceImpl.unsafeReactivateNamespace((io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceResponse>) responseObserver);
          break;
        case METHODID_UNSAFE_DELETE_NAMESPACE:
          serviceImpl.unsafeDeleteNamespace((io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceResponse>) responseObserver);
          break;
        case METHODID_UNSAFE_UPDATE_ATTRIBUTE:
          serviceImpl.unsafeUpdateAttribute((io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeResponse>) responseObserver);
          break;
        case METHODID_UNSAFE_REACTIVATE_ATTRIBUTE:
          serviceImpl.unsafeReactivateAttribute((io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeResponse>) responseObserver);
          break;
        case METHODID_UNSAFE_DELETE_ATTRIBUTE:
          serviceImpl.unsafeDeleteAttribute((io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeResponse>) responseObserver);
          break;
        case METHODID_UNSAFE_UPDATE_ATTRIBUTE_VALUE:
          serviceImpl.unsafeUpdateAttributeValue((io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueResponse>) responseObserver);
          break;
        case METHODID_UNSAFE_REACTIVATE_ATTRIBUTE_VALUE:
          serviceImpl.unsafeReactivateAttributeValue((io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueResponse>) responseObserver);
          break;
        case METHODID_UNSAFE_DELETE_ATTRIBUTE_VALUE:
          serviceImpl.unsafeDeleteAttributeValue((io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueResponse>) responseObserver);
          break;
        default:
          throw new AssertionError();
      }
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public io.grpc.stub.StreamObserver<Req> invoke(
        io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        default:
          throw new AssertionError();
      }
    }
  }

  public static final io.grpc.ServerServiceDefinition bindService(AsyncService service) {
    return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
        .addMethod(
          getUnsafeUpdateNamespaceMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceRequest,
              io.opentdf.platform.policy.unsafe.UnsafeUpdateNamespaceResponse>(
                service, METHODID_UNSAFE_UPDATE_NAMESPACE)))
        .addMethod(
          getUnsafeReactivateNamespaceMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceRequest,
              io.opentdf.platform.policy.unsafe.UnsafeReactivateNamespaceResponse>(
                service, METHODID_UNSAFE_REACTIVATE_NAMESPACE)))
        .addMethod(
          getUnsafeDeleteNamespaceMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceRequest,
              io.opentdf.platform.policy.unsafe.UnsafeDeleteNamespaceResponse>(
                service, METHODID_UNSAFE_DELETE_NAMESPACE)))
        .addMethod(
          getUnsafeUpdateAttributeMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeRequest,
              io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeResponse>(
                service, METHODID_UNSAFE_UPDATE_ATTRIBUTE)))
        .addMethod(
          getUnsafeReactivateAttributeMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeRequest,
              io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeResponse>(
                service, METHODID_UNSAFE_REACTIVATE_ATTRIBUTE)))
        .addMethod(
          getUnsafeDeleteAttributeMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeRequest,
              io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeResponse>(
                service, METHODID_UNSAFE_DELETE_ATTRIBUTE)))
        .addMethod(
          getUnsafeUpdateAttributeValueMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueRequest,
              io.opentdf.platform.policy.unsafe.UnsafeUpdateAttributeValueResponse>(
                service, METHODID_UNSAFE_UPDATE_ATTRIBUTE_VALUE)))
        .addMethod(
          getUnsafeReactivateAttributeValueMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueRequest,
              io.opentdf.platform.policy.unsafe.UnsafeReactivateAttributeValueResponse>(
                service, METHODID_UNSAFE_REACTIVATE_ATTRIBUTE_VALUE)))
        .addMethod(
          getUnsafeDeleteAttributeValueMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueRequest,
              io.opentdf.platform.policy.unsafe.UnsafeDeleteAttributeValueResponse>(
                service, METHODID_UNSAFE_DELETE_ATTRIBUTE_VALUE)))
        .build();
  }

  private static abstract class UnsafeServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    UnsafeServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return io.opentdf.platform.policy.unsafe.UnsafeProto.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("UnsafeService");
    }
  }

  private static final class UnsafeServiceFileDescriptorSupplier
      extends UnsafeServiceBaseDescriptorSupplier {
    UnsafeServiceFileDescriptorSupplier() {}
  }

  private static final class UnsafeServiceMethodDescriptorSupplier
      extends UnsafeServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final java.lang.String methodName;

    UnsafeServiceMethodDescriptorSupplier(java.lang.String methodName) {
      this.methodName = methodName;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.MethodDescriptor getMethodDescriptor() {
      return getServiceDescriptor().findMethodByName(methodName);
    }
  }

  private static volatile io.grpc.ServiceDescriptor serviceDescriptor;

  public static io.grpc.ServiceDescriptor getServiceDescriptor() {
    io.grpc.ServiceDescriptor result = serviceDescriptor;
    if (result == null) {
      synchronized (UnsafeServiceGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new UnsafeServiceFileDescriptorSupplier())
              .addMethod(getUnsafeUpdateNamespaceMethod())
              .addMethod(getUnsafeReactivateNamespaceMethod())
              .addMethod(getUnsafeDeleteNamespaceMethod())
              .addMethod(getUnsafeUpdateAttributeMethod())
              .addMethod(getUnsafeReactivateAttributeMethod())
              .addMethod(getUnsafeDeleteAttributeMethod())
              .addMethod(getUnsafeUpdateAttributeValueMethod())
              .addMethod(getUnsafeReactivateAttributeValueMethod())
              .addMethod(getUnsafeDeleteAttributeValueMethod())
              .build();
        }
      }
    }
    return result;
  }
}
