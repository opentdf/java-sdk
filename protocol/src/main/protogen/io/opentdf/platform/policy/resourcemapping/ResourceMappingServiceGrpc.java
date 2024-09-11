package io.opentdf.platform.policy.resourcemapping;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 * <pre>
 *Resource Mapping Groups
 * </pre>
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.61.1)",
    comments = "Source: policy/resourcemapping/resource_mapping.proto")
@io.grpc.stub.annotations.GrpcGenerated
public final class ResourceMappingServiceGrpc {

  private ResourceMappingServiceGrpc() {}

  public static final java.lang.String SERVICE_NAME = "policy.resourcemapping.ResourceMappingService";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsRequest,
      io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsResponse> getListResourceMappingGroupsMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ListResourceMappingGroups",
      requestType = io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsRequest.class,
      responseType = io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsRequest,
      io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsResponse> getListResourceMappingGroupsMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsRequest, io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsResponse> getListResourceMappingGroupsMethod;
    if ((getListResourceMappingGroupsMethod = ResourceMappingServiceGrpc.getListResourceMappingGroupsMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getListResourceMappingGroupsMethod = ResourceMappingServiceGrpc.getListResourceMappingGroupsMethod) == null) {
          ResourceMappingServiceGrpc.getListResourceMappingGroupsMethod = getListResourceMappingGroupsMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsRequest, io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ListResourceMappingGroups"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("ListResourceMappingGroups"))
              .build();
        }
      }
    }
    return getListResourceMappingGroupsMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupRequest,
      io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupResponse> getGetResourceMappingGroupMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetResourceMappingGroup",
      requestType = io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupRequest.class,
      responseType = io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupRequest,
      io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupResponse> getGetResourceMappingGroupMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupRequest, io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupResponse> getGetResourceMappingGroupMethod;
    if ((getGetResourceMappingGroupMethod = ResourceMappingServiceGrpc.getGetResourceMappingGroupMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getGetResourceMappingGroupMethod = ResourceMappingServiceGrpc.getGetResourceMappingGroupMethod) == null) {
          ResourceMappingServiceGrpc.getGetResourceMappingGroupMethod = getGetResourceMappingGroupMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupRequest, io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetResourceMappingGroup"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("GetResourceMappingGroup"))
              .build();
        }
      }
    }
    return getGetResourceMappingGroupMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupRequest,
      io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupResponse> getCreateResourceMappingGroupMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CreateResourceMappingGroup",
      requestType = io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupRequest.class,
      responseType = io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupRequest,
      io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupResponse> getCreateResourceMappingGroupMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupRequest, io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupResponse> getCreateResourceMappingGroupMethod;
    if ((getCreateResourceMappingGroupMethod = ResourceMappingServiceGrpc.getCreateResourceMappingGroupMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getCreateResourceMappingGroupMethod = ResourceMappingServiceGrpc.getCreateResourceMappingGroupMethod) == null) {
          ResourceMappingServiceGrpc.getCreateResourceMappingGroupMethod = getCreateResourceMappingGroupMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupRequest, io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CreateResourceMappingGroup"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("CreateResourceMappingGroup"))
              .build();
        }
      }
    }
    return getCreateResourceMappingGroupMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupRequest,
      io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupResponse> getUpdateResourceMappingGroupMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UpdateResourceMappingGroup",
      requestType = io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupRequest.class,
      responseType = io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupRequest,
      io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupResponse> getUpdateResourceMappingGroupMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupRequest, io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupResponse> getUpdateResourceMappingGroupMethod;
    if ((getUpdateResourceMappingGroupMethod = ResourceMappingServiceGrpc.getUpdateResourceMappingGroupMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getUpdateResourceMappingGroupMethod = ResourceMappingServiceGrpc.getUpdateResourceMappingGroupMethod) == null) {
          ResourceMappingServiceGrpc.getUpdateResourceMappingGroupMethod = getUpdateResourceMappingGroupMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupRequest, io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UpdateResourceMappingGroup"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("UpdateResourceMappingGroup"))
              .build();
        }
      }
    }
    return getUpdateResourceMappingGroupMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupRequest,
      io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupResponse> getDeleteResourceMappingGroupMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DeleteResourceMappingGroup",
      requestType = io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupRequest.class,
      responseType = io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupRequest,
      io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupResponse> getDeleteResourceMappingGroupMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupRequest, io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupResponse> getDeleteResourceMappingGroupMethod;
    if ((getDeleteResourceMappingGroupMethod = ResourceMappingServiceGrpc.getDeleteResourceMappingGroupMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getDeleteResourceMappingGroupMethod = ResourceMappingServiceGrpc.getDeleteResourceMappingGroupMethod) == null) {
          ResourceMappingServiceGrpc.getDeleteResourceMappingGroupMethod = getDeleteResourceMappingGroupMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupRequest, io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DeleteResourceMappingGroup"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("DeleteResourceMappingGroup"))
              .build();
        }
      }
    }
    return getDeleteResourceMappingGroupMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsRequest,
      io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse> getListResourceMappingsMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ListResourceMappings",
      requestType = io.opentdf.platform.policy.resourcemapping.ListResourceMappingsRequest.class,
      responseType = io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsRequest,
      io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse> getListResourceMappingsMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsRequest, io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse> getListResourceMappingsMethod;
    if ((getListResourceMappingsMethod = ResourceMappingServiceGrpc.getListResourceMappingsMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getListResourceMappingsMethod = ResourceMappingServiceGrpc.getListResourceMappingsMethod) == null) {
          ResourceMappingServiceGrpc.getListResourceMappingsMethod = getListResourceMappingsMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsRequest, io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ListResourceMappings"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.ListResourceMappingsRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("ListResourceMappings"))
              .build();
        }
      }
    }
    return getListResourceMappingsMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsRequest,
      io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsResponse> getListResourceMappingsByGroupFqnsMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ListResourceMappingsByGroupFqns",
      requestType = io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsRequest.class,
      responseType = io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsRequest,
      io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsResponse> getListResourceMappingsByGroupFqnsMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsRequest, io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsResponse> getListResourceMappingsByGroupFqnsMethod;
    if ((getListResourceMappingsByGroupFqnsMethod = ResourceMappingServiceGrpc.getListResourceMappingsByGroupFqnsMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getListResourceMappingsByGroupFqnsMethod = ResourceMappingServiceGrpc.getListResourceMappingsByGroupFqnsMethod) == null) {
          ResourceMappingServiceGrpc.getListResourceMappingsByGroupFqnsMethod = getListResourceMappingsByGroupFqnsMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsRequest, io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ListResourceMappingsByGroupFqns"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("ListResourceMappingsByGroupFqns"))
              .build();
        }
      }
    }
    return getListResourceMappingsByGroupFqnsMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.GetResourceMappingRequest,
      io.opentdf.platform.policy.resourcemapping.GetResourceMappingResponse> getGetResourceMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetResourceMapping",
      requestType = io.opentdf.platform.policy.resourcemapping.GetResourceMappingRequest.class,
      responseType = io.opentdf.platform.policy.resourcemapping.GetResourceMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.GetResourceMappingRequest,
      io.opentdf.platform.policy.resourcemapping.GetResourceMappingResponse> getGetResourceMappingMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.GetResourceMappingRequest, io.opentdf.platform.policy.resourcemapping.GetResourceMappingResponse> getGetResourceMappingMethod;
    if ((getGetResourceMappingMethod = ResourceMappingServiceGrpc.getGetResourceMappingMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getGetResourceMappingMethod = ResourceMappingServiceGrpc.getGetResourceMappingMethod) == null) {
          ResourceMappingServiceGrpc.getGetResourceMappingMethod = getGetResourceMappingMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.resourcemapping.GetResourceMappingRequest, io.opentdf.platform.policy.resourcemapping.GetResourceMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetResourceMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.GetResourceMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.GetResourceMappingResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("GetResourceMapping"))
              .build();
        }
      }
    }
    return getGetResourceMappingMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingRequest,
      io.opentdf.platform.policy.resourcemapping.CreateResourceMappingResponse> getCreateResourceMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CreateResourceMapping",
      requestType = io.opentdf.platform.policy.resourcemapping.CreateResourceMappingRequest.class,
      responseType = io.opentdf.platform.policy.resourcemapping.CreateResourceMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingRequest,
      io.opentdf.platform.policy.resourcemapping.CreateResourceMappingResponse> getCreateResourceMappingMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingRequest, io.opentdf.platform.policy.resourcemapping.CreateResourceMappingResponse> getCreateResourceMappingMethod;
    if ((getCreateResourceMappingMethod = ResourceMappingServiceGrpc.getCreateResourceMappingMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getCreateResourceMappingMethod = ResourceMappingServiceGrpc.getCreateResourceMappingMethod) == null) {
          ResourceMappingServiceGrpc.getCreateResourceMappingMethod = getCreateResourceMappingMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingRequest, io.opentdf.platform.policy.resourcemapping.CreateResourceMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CreateResourceMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.CreateResourceMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.CreateResourceMappingResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("CreateResourceMapping"))
              .build();
        }
      }
    }
    return getCreateResourceMappingMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingRequest,
      io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingResponse> getUpdateResourceMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UpdateResourceMapping",
      requestType = io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingRequest.class,
      responseType = io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingRequest,
      io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingResponse> getUpdateResourceMappingMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingRequest, io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingResponse> getUpdateResourceMappingMethod;
    if ((getUpdateResourceMappingMethod = ResourceMappingServiceGrpc.getUpdateResourceMappingMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getUpdateResourceMappingMethod = ResourceMappingServiceGrpc.getUpdateResourceMappingMethod) == null) {
          ResourceMappingServiceGrpc.getUpdateResourceMappingMethod = getUpdateResourceMappingMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingRequest, io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UpdateResourceMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("UpdateResourceMapping"))
              .build();
        }
      }
    }
    return getUpdateResourceMappingMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingRequest,
      io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingResponse> getDeleteResourceMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DeleteResourceMapping",
      requestType = io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingRequest.class,
      responseType = io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingRequest,
      io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingResponse> getDeleteResourceMappingMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingRequest, io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingResponse> getDeleteResourceMappingMethod;
    if ((getDeleteResourceMappingMethod = ResourceMappingServiceGrpc.getDeleteResourceMappingMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getDeleteResourceMappingMethod = ResourceMappingServiceGrpc.getDeleteResourceMappingMethod) == null) {
          ResourceMappingServiceGrpc.getDeleteResourceMappingMethod = getDeleteResourceMappingMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingRequest, io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DeleteResourceMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("DeleteResourceMapping"))
              .build();
        }
      }
    }
    return getDeleteResourceMappingMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static ResourceMappingServiceStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<ResourceMappingServiceStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<ResourceMappingServiceStub>() {
        @java.lang.Override
        public ResourceMappingServiceStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new ResourceMappingServiceStub(channel, callOptions);
        }
      };
    return ResourceMappingServiceStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static ResourceMappingServiceBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<ResourceMappingServiceBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<ResourceMappingServiceBlockingStub>() {
        @java.lang.Override
        public ResourceMappingServiceBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new ResourceMappingServiceBlockingStub(channel, callOptions);
        }
      };
    return ResourceMappingServiceBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static ResourceMappingServiceFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<ResourceMappingServiceFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<ResourceMappingServiceFutureStub>() {
        @java.lang.Override
        public ResourceMappingServiceFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new ResourceMappingServiceFutureStub(channel, callOptions);
        }
      };
    return ResourceMappingServiceFutureStub.newStub(factory, channel);
  }

  /**
   * <pre>
   *Resource Mapping Groups
   * </pre>
   */
  public interface AsyncService {

    /**
     */
    default void listResourceMappingGroups(io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getListResourceMappingGroupsMethod(), responseObserver);
    }

    /**
     */
    default void getResourceMappingGroup(io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetResourceMappingGroupMethod(), responseObserver);
    }

    /**
     */
    default void createResourceMappingGroup(io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCreateResourceMappingGroupMethod(), responseObserver);
    }

    /**
     */
    default void updateResourceMappingGroup(io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUpdateResourceMappingGroupMethod(), responseObserver);
    }

    /**
     */
    default void deleteResourceMappingGroup(io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDeleteResourceMappingGroupMethod(), responseObserver);
    }

    /**
     */
    default void listResourceMappings(io.opentdf.platform.policy.resourcemapping.ListResourceMappingsRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getListResourceMappingsMethod(), responseObserver);
    }

    /**
     */
    default void listResourceMappingsByGroupFqns(io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getListResourceMappingsByGroupFqnsMethod(), responseObserver);
    }

    /**
     */
    default void getResourceMapping(io.opentdf.platform.policy.resourcemapping.GetResourceMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.GetResourceMappingResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetResourceMappingMethod(), responseObserver);
    }

    /**
     */
    default void createResourceMapping(io.opentdf.platform.policy.resourcemapping.CreateResourceMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCreateResourceMappingMethod(), responseObserver);
    }

    /**
     */
    default void updateResourceMapping(io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUpdateResourceMappingMethod(), responseObserver);
    }

    /**
     */
    default void deleteResourceMapping(io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDeleteResourceMappingMethod(), responseObserver);
    }
  }

  /**
   * Base class for the server implementation of the service ResourceMappingService.
   * <pre>
   *Resource Mapping Groups
   * </pre>
   */
  public static abstract class ResourceMappingServiceImplBase
      implements io.grpc.BindableService, AsyncService {

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return ResourceMappingServiceGrpc.bindService(this);
    }
  }

  /**
   * A stub to allow clients to do asynchronous rpc calls to service ResourceMappingService.
   * <pre>
   *Resource Mapping Groups
   * </pre>
   */
  public static final class ResourceMappingServiceStub
      extends io.grpc.stub.AbstractAsyncStub<ResourceMappingServiceStub> {
    private ResourceMappingServiceStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected ResourceMappingServiceStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new ResourceMappingServiceStub(channel, callOptions);
    }

    /**
     */
    public void listResourceMappingGroups(io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getListResourceMappingGroupsMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void getResourceMappingGroup(io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetResourceMappingGroupMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void createResourceMappingGroup(io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCreateResourceMappingGroupMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void updateResourceMappingGroup(io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUpdateResourceMappingGroupMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void deleteResourceMappingGroup(io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDeleteResourceMappingGroupMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void listResourceMappings(io.opentdf.platform.policy.resourcemapping.ListResourceMappingsRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getListResourceMappingsMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void listResourceMappingsByGroupFqns(io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getListResourceMappingsByGroupFqnsMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void getResourceMapping(io.opentdf.platform.policy.resourcemapping.GetResourceMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.GetResourceMappingResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetResourceMappingMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void createResourceMapping(io.opentdf.platform.policy.resourcemapping.CreateResourceMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCreateResourceMappingMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void updateResourceMapping(io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUpdateResourceMappingMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void deleteResourceMapping(io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDeleteResourceMappingMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   * A stub to allow clients to do synchronous rpc calls to service ResourceMappingService.
   * <pre>
   *Resource Mapping Groups
   * </pre>
   */
  public static final class ResourceMappingServiceBlockingStub
      extends io.grpc.stub.AbstractBlockingStub<ResourceMappingServiceBlockingStub> {
    private ResourceMappingServiceBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected ResourceMappingServiceBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new ResourceMappingServiceBlockingStub(channel, callOptions);
    }

    /**
     */
    public io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsResponse listResourceMappingGroups(io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getListResourceMappingGroupsMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupResponse getResourceMappingGroup(io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetResourceMappingGroupMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupResponse createResourceMappingGroup(io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCreateResourceMappingGroupMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupResponse updateResourceMappingGroup(io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUpdateResourceMappingGroupMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupResponse deleteResourceMappingGroup(io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDeleteResourceMappingGroupMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse listResourceMappings(io.opentdf.platform.policy.resourcemapping.ListResourceMappingsRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getListResourceMappingsMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsResponse listResourceMappingsByGroupFqns(io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getListResourceMappingsByGroupFqnsMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.resourcemapping.GetResourceMappingResponse getResourceMapping(io.opentdf.platform.policy.resourcemapping.GetResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetResourceMappingMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.resourcemapping.CreateResourceMappingResponse createResourceMapping(io.opentdf.platform.policy.resourcemapping.CreateResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCreateResourceMappingMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingResponse updateResourceMapping(io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUpdateResourceMappingMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingResponse deleteResourceMapping(io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDeleteResourceMappingMethod(), getCallOptions(), request);
    }
  }

  /**
   * A stub to allow clients to do ListenableFuture-style rpc calls to service ResourceMappingService.
   * <pre>
   *Resource Mapping Groups
   * </pre>
   */
  public static final class ResourceMappingServiceFutureStub
      extends io.grpc.stub.AbstractFutureStub<ResourceMappingServiceFutureStub> {
    private ResourceMappingServiceFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected ResourceMappingServiceFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new ResourceMappingServiceFutureStub(channel, callOptions);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsResponse> listResourceMappingGroups(
        io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getListResourceMappingGroupsMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupResponse> getResourceMappingGroup(
        io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetResourceMappingGroupMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupResponse> createResourceMappingGroup(
        io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCreateResourceMappingGroupMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupResponse> updateResourceMappingGroup(
        io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUpdateResourceMappingGroupMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupResponse> deleteResourceMappingGroup(
        io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDeleteResourceMappingGroupMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse> listResourceMappings(
        io.opentdf.platform.policy.resourcemapping.ListResourceMappingsRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getListResourceMappingsMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsResponse> listResourceMappingsByGroupFqns(
        io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getListResourceMappingsByGroupFqnsMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.resourcemapping.GetResourceMappingResponse> getResourceMapping(
        io.opentdf.platform.policy.resourcemapping.GetResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetResourceMappingMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingResponse> createResourceMapping(
        io.opentdf.platform.policy.resourcemapping.CreateResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCreateResourceMappingMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingResponse> updateResourceMapping(
        io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUpdateResourceMappingMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingResponse> deleteResourceMapping(
        io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDeleteResourceMappingMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_LIST_RESOURCE_MAPPING_GROUPS = 0;
  private static final int METHODID_GET_RESOURCE_MAPPING_GROUP = 1;
  private static final int METHODID_CREATE_RESOURCE_MAPPING_GROUP = 2;
  private static final int METHODID_UPDATE_RESOURCE_MAPPING_GROUP = 3;
  private static final int METHODID_DELETE_RESOURCE_MAPPING_GROUP = 4;
  private static final int METHODID_LIST_RESOURCE_MAPPINGS = 5;
  private static final int METHODID_LIST_RESOURCE_MAPPINGS_BY_GROUP_FQNS = 6;
  private static final int METHODID_GET_RESOURCE_MAPPING = 7;
  private static final int METHODID_CREATE_RESOURCE_MAPPING = 8;
  private static final int METHODID_UPDATE_RESOURCE_MAPPING = 9;
  private static final int METHODID_DELETE_RESOURCE_MAPPING = 10;

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
        case METHODID_LIST_RESOURCE_MAPPING_GROUPS:
          serviceImpl.listResourceMappingGroups((io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsResponse>) responseObserver);
          break;
        case METHODID_GET_RESOURCE_MAPPING_GROUP:
          serviceImpl.getResourceMappingGroup((io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupResponse>) responseObserver);
          break;
        case METHODID_CREATE_RESOURCE_MAPPING_GROUP:
          serviceImpl.createResourceMappingGroup((io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupResponse>) responseObserver);
          break;
        case METHODID_UPDATE_RESOURCE_MAPPING_GROUP:
          serviceImpl.updateResourceMappingGroup((io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupResponse>) responseObserver);
          break;
        case METHODID_DELETE_RESOURCE_MAPPING_GROUP:
          serviceImpl.deleteResourceMappingGroup((io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupResponse>) responseObserver);
          break;
        case METHODID_LIST_RESOURCE_MAPPINGS:
          serviceImpl.listResourceMappings((io.opentdf.platform.policy.resourcemapping.ListResourceMappingsRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse>) responseObserver);
          break;
        case METHODID_LIST_RESOURCE_MAPPINGS_BY_GROUP_FQNS:
          serviceImpl.listResourceMappingsByGroupFqns((io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsResponse>) responseObserver);
          break;
        case METHODID_GET_RESOURCE_MAPPING:
          serviceImpl.getResourceMapping((io.opentdf.platform.policy.resourcemapping.GetResourceMappingRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.GetResourceMappingResponse>) responseObserver);
          break;
        case METHODID_CREATE_RESOURCE_MAPPING:
          serviceImpl.createResourceMapping((io.opentdf.platform.policy.resourcemapping.CreateResourceMappingRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.CreateResourceMappingResponse>) responseObserver);
          break;
        case METHODID_UPDATE_RESOURCE_MAPPING:
          serviceImpl.updateResourceMapping((io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingResponse>) responseObserver);
          break;
        case METHODID_DELETE_RESOURCE_MAPPING:
          serviceImpl.deleteResourceMapping((io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingResponse>) responseObserver);
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
          getListResourceMappingGroupsMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsRequest,
              io.opentdf.platform.policy.resourcemapping.ListResourceMappingGroupsResponse>(
                service, METHODID_LIST_RESOURCE_MAPPING_GROUPS)))
        .addMethod(
          getGetResourceMappingGroupMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupRequest,
              io.opentdf.platform.policy.resourcemapping.GetResourceMappingGroupResponse>(
                service, METHODID_GET_RESOURCE_MAPPING_GROUP)))
        .addMethod(
          getCreateResourceMappingGroupMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupRequest,
              io.opentdf.platform.policy.resourcemapping.CreateResourceMappingGroupResponse>(
                service, METHODID_CREATE_RESOURCE_MAPPING_GROUP)))
        .addMethod(
          getUpdateResourceMappingGroupMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupRequest,
              io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingGroupResponse>(
                service, METHODID_UPDATE_RESOURCE_MAPPING_GROUP)))
        .addMethod(
          getDeleteResourceMappingGroupMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupRequest,
              io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingGroupResponse>(
                service, METHODID_DELETE_RESOURCE_MAPPING_GROUP)))
        .addMethod(
          getListResourceMappingsMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.resourcemapping.ListResourceMappingsRequest,
              io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse>(
                service, METHODID_LIST_RESOURCE_MAPPINGS)))
        .addMethod(
          getListResourceMappingsByGroupFqnsMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsRequest,
              io.opentdf.platform.policy.resourcemapping.ListResourceMappingsByGroupFqnsResponse>(
                service, METHODID_LIST_RESOURCE_MAPPINGS_BY_GROUP_FQNS)))
        .addMethod(
          getGetResourceMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.resourcemapping.GetResourceMappingRequest,
              io.opentdf.platform.policy.resourcemapping.GetResourceMappingResponse>(
                service, METHODID_GET_RESOURCE_MAPPING)))
        .addMethod(
          getCreateResourceMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.resourcemapping.CreateResourceMappingRequest,
              io.opentdf.platform.policy.resourcemapping.CreateResourceMappingResponse>(
                service, METHODID_CREATE_RESOURCE_MAPPING)))
        .addMethod(
          getUpdateResourceMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingRequest,
              io.opentdf.platform.policy.resourcemapping.UpdateResourceMappingResponse>(
                service, METHODID_UPDATE_RESOURCE_MAPPING)))
        .addMethod(
          getDeleteResourceMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingRequest,
              io.opentdf.platform.policy.resourcemapping.DeleteResourceMappingResponse>(
                service, METHODID_DELETE_RESOURCE_MAPPING)))
        .build();
  }

  private static abstract class ResourceMappingServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    ResourceMappingServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return io.opentdf.platform.policy.resourcemapping.ResourceMappingProto.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("ResourceMappingService");
    }
  }

  private static final class ResourceMappingServiceFileDescriptorSupplier
      extends ResourceMappingServiceBaseDescriptorSupplier {
    ResourceMappingServiceFileDescriptorSupplier() {}
  }

  private static final class ResourceMappingServiceMethodDescriptorSupplier
      extends ResourceMappingServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final java.lang.String methodName;

    ResourceMappingServiceMethodDescriptorSupplier(java.lang.String methodName) {
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
      synchronized (ResourceMappingServiceGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new ResourceMappingServiceFileDescriptorSupplier())
              .addMethod(getListResourceMappingGroupsMethod())
              .addMethod(getGetResourceMappingGroupMethod())
              .addMethod(getCreateResourceMappingGroupMethod())
              .addMethod(getUpdateResourceMappingGroupMethod())
              .addMethod(getDeleteResourceMappingGroupMethod())
              .addMethod(getListResourceMappingsMethod())
              .addMethod(getListResourceMappingsByGroupFqnsMethod())
              .addMethod(getGetResourceMappingMethod())
              .addMethod(getCreateResourceMappingMethod())
              .addMethod(getUpdateResourceMappingMethod())
              .addMethod(getDeleteResourceMappingMethod())
              .build();
        }
      }
    }
    return result;
  }
}
