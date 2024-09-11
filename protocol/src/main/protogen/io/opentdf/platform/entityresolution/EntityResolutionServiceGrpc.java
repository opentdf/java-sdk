package io.opentdf.platform.entityresolution;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.61.1)",
    comments = "Source: entityresolution/entity_resolution.proto")
@io.grpc.stub.annotations.GrpcGenerated
public final class EntityResolutionServiceGrpc {

  private EntityResolutionServiceGrpc() {}

  public static final java.lang.String SERVICE_NAME = "entityresolution.EntityResolutionService";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.entityresolution.ResolveEntitiesRequest,
      io.opentdf.platform.entityresolution.ResolveEntitiesResponse> getResolveEntitiesMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ResolveEntities",
      requestType = io.opentdf.platform.entityresolution.ResolveEntitiesRequest.class,
      responseType = io.opentdf.platform.entityresolution.ResolveEntitiesResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.entityresolution.ResolveEntitiesRequest,
      io.opentdf.platform.entityresolution.ResolveEntitiesResponse> getResolveEntitiesMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.entityresolution.ResolveEntitiesRequest, io.opentdf.platform.entityresolution.ResolveEntitiesResponse> getResolveEntitiesMethod;
    if ((getResolveEntitiesMethod = EntityResolutionServiceGrpc.getResolveEntitiesMethod) == null) {
      synchronized (EntityResolutionServiceGrpc.class) {
        if ((getResolveEntitiesMethod = EntityResolutionServiceGrpc.getResolveEntitiesMethod) == null) {
          EntityResolutionServiceGrpc.getResolveEntitiesMethod = getResolveEntitiesMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.entityresolution.ResolveEntitiesRequest, io.opentdf.platform.entityresolution.ResolveEntitiesResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ResolveEntities"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.entityresolution.ResolveEntitiesRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.entityresolution.ResolveEntitiesResponse.getDefaultInstance()))
              .setSchemaDescriptor(new EntityResolutionServiceMethodDescriptorSupplier("ResolveEntities"))
              .build();
        }
      }
    }
    return getResolveEntitiesMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.entityresolution.CreateEntityChainFromJwtRequest,
      io.opentdf.platform.entityresolution.CreateEntityChainFromJwtResponse> getCreateEntityChainFromJwtMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CreateEntityChainFromJwt",
      requestType = io.opentdf.platform.entityresolution.CreateEntityChainFromJwtRequest.class,
      responseType = io.opentdf.platform.entityresolution.CreateEntityChainFromJwtResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.entityresolution.CreateEntityChainFromJwtRequest,
      io.opentdf.platform.entityresolution.CreateEntityChainFromJwtResponse> getCreateEntityChainFromJwtMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.entityresolution.CreateEntityChainFromJwtRequest, io.opentdf.platform.entityresolution.CreateEntityChainFromJwtResponse> getCreateEntityChainFromJwtMethod;
    if ((getCreateEntityChainFromJwtMethod = EntityResolutionServiceGrpc.getCreateEntityChainFromJwtMethod) == null) {
      synchronized (EntityResolutionServiceGrpc.class) {
        if ((getCreateEntityChainFromJwtMethod = EntityResolutionServiceGrpc.getCreateEntityChainFromJwtMethod) == null) {
          EntityResolutionServiceGrpc.getCreateEntityChainFromJwtMethod = getCreateEntityChainFromJwtMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.entityresolution.CreateEntityChainFromJwtRequest, io.opentdf.platform.entityresolution.CreateEntityChainFromJwtResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CreateEntityChainFromJwt"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.entityresolution.CreateEntityChainFromJwtRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.entityresolution.CreateEntityChainFromJwtResponse.getDefaultInstance()))
              .setSchemaDescriptor(new EntityResolutionServiceMethodDescriptorSupplier("CreateEntityChainFromJwt"))
              .build();
        }
      }
    }
    return getCreateEntityChainFromJwtMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static EntityResolutionServiceStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<EntityResolutionServiceStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<EntityResolutionServiceStub>() {
        @java.lang.Override
        public EntityResolutionServiceStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new EntityResolutionServiceStub(channel, callOptions);
        }
      };
    return EntityResolutionServiceStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static EntityResolutionServiceBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<EntityResolutionServiceBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<EntityResolutionServiceBlockingStub>() {
        @java.lang.Override
        public EntityResolutionServiceBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new EntityResolutionServiceBlockingStub(channel, callOptions);
        }
      };
    return EntityResolutionServiceBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static EntityResolutionServiceFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<EntityResolutionServiceFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<EntityResolutionServiceFutureStub>() {
        @java.lang.Override
        public EntityResolutionServiceFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new EntityResolutionServiceFutureStub(channel, callOptions);
        }
      };
    return EntityResolutionServiceFutureStub.newStub(factory, channel);
  }

  /**
   */
  public interface AsyncService {

    /**
     */
    default void resolveEntities(io.opentdf.platform.entityresolution.ResolveEntitiesRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.entityresolution.ResolveEntitiesResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getResolveEntitiesMethod(), responseObserver);
    }

    /**
     */
    default void createEntityChainFromJwt(io.opentdf.platform.entityresolution.CreateEntityChainFromJwtRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.entityresolution.CreateEntityChainFromJwtResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCreateEntityChainFromJwtMethod(), responseObserver);
    }
  }

  /**
   * Base class for the server implementation of the service EntityResolutionService.
   */
  public static abstract class EntityResolutionServiceImplBase
      implements io.grpc.BindableService, AsyncService {

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return EntityResolutionServiceGrpc.bindService(this);
    }
  }

  /**
   * A stub to allow clients to do asynchronous rpc calls to service EntityResolutionService.
   */
  public static final class EntityResolutionServiceStub
      extends io.grpc.stub.AbstractAsyncStub<EntityResolutionServiceStub> {
    private EntityResolutionServiceStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected EntityResolutionServiceStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new EntityResolutionServiceStub(channel, callOptions);
    }

    /**
     */
    public void resolveEntities(io.opentdf.platform.entityresolution.ResolveEntitiesRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.entityresolution.ResolveEntitiesResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getResolveEntitiesMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void createEntityChainFromJwt(io.opentdf.platform.entityresolution.CreateEntityChainFromJwtRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.entityresolution.CreateEntityChainFromJwtResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCreateEntityChainFromJwtMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   * A stub to allow clients to do synchronous rpc calls to service EntityResolutionService.
   */
  public static final class EntityResolutionServiceBlockingStub
      extends io.grpc.stub.AbstractBlockingStub<EntityResolutionServiceBlockingStub> {
    private EntityResolutionServiceBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected EntityResolutionServiceBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new EntityResolutionServiceBlockingStub(channel, callOptions);
    }

    /**
     */
    public io.opentdf.platform.entityresolution.ResolveEntitiesResponse resolveEntities(io.opentdf.platform.entityresolution.ResolveEntitiesRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getResolveEntitiesMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.entityresolution.CreateEntityChainFromJwtResponse createEntityChainFromJwt(io.opentdf.platform.entityresolution.CreateEntityChainFromJwtRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCreateEntityChainFromJwtMethod(), getCallOptions(), request);
    }
  }

  /**
   * A stub to allow clients to do ListenableFuture-style rpc calls to service EntityResolutionService.
   */
  public static final class EntityResolutionServiceFutureStub
      extends io.grpc.stub.AbstractFutureStub<EntityResolutionServiceFutureStub> {
    private EntityResolutionServiceFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected EntityResolutionServiceFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new EntityResolutionServiceFutureStub(channel, callOptions);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.entityresolution.ResolveEntitiesResponse> resolveEntities(
        io.opentdf.platform.entityresolution.ResolveEntitiesRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getResolveEntitiesMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.entityresolution.CreateEntityChainFromJwtResponse> createEntityChainFromJwt(
        io.opentdf.platform.entityresolution.CreateEntityChainFromJwtRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCreateEntityChainFromJwtMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_RESOLVE_ENTITIES = 0;
  private static final int METHODID_CREATE_ENTITY_CHAIN_FROM_JWT = 1;

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
        case METHODID_RESOLVE_ENTITIES:
          serviceImpl.resolveEntities((io.opentdf.platform.entityresolution.ResolveEntitiesRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.entityresolution.ResolveEntitiesResponse>) responseObserver);
          break;
        case METHODID_CREATE_ENTITY_CHAIN_FROM_JWT:
          serviceImpl.createEntityChainFromJwt((io.opentdf.platform.entityresolution.CreateEntityChainFromJwtRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.entityresolution.CreateEntityChainFromJwtResponse>) responseObserver);
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
          getResolveEntitiesMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.entityresolution.ResolveEntitiesRequest,
              io.opentdf.platform.entityresolution.ResolveEntitiesResponse>(
                service, METHODID_RESOLVE_ENTITIES)))
        .addMethod(
          getCreateEntityChainFromJwtMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.entityresolution.CreateEntityChainFromJwtRequest,
              io.opentdf.platform.entityresolution.CreateEntityChainFromJwtResponse>(
                service, METHODID_CREATE_ENTITY_CHAIN_FROM_JWT)))
        .build();
  }

  private static abstract class EntityResolutionServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    EntityResolutionServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return io.opentdf.platform.entityresolution.EntityResolutionProto.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("EntityResolutionService");
    }
  }

  private static final class EntityResolutionServiceFileDescriptorSupplier
      extends EntityResolutionServiceBaseDescriptorSupplier {
    EntityResolutionServiceFileDescriptorSupplier() {}
  }

  private static final class EntityResolutionServiceMethodDescriptorSupplier
      extends EntityResolutionServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final java.lang.String methodName;

    EntityResolutionServiceMethodDescriptorSupplier(java.lang.String methodName) {
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
      synchronized (EntityResolutionServiceGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new EntityResolutionServiceFileDescriptorSupplier())
              .addMethod(getResolveEntitiesMethod())
              .addMethod(getCreateEntityChainFromJwtMethod())
              .build();
        }
      }
    }
    return result;
  }
}
