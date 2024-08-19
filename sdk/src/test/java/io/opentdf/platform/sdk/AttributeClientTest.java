package io.opentdf.platform.sdk;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsRequest;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsResponse;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsResponse.AttributeAndValue;
import io.opentdf.platform.policy.Attribute;
import io.opentdf.platform.policy.Namespace;
import io.opentdf.platform.policy.Value;
import io.opentdf.platform.policy.AttributeRuleTypeEnum;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import static io.opentdf.platform.sdk.SDKBuilderTest.getRandomPort;
import static org.assertj.core.api.Assertions.assertThat;


public class AttributeClientTest {
    @Test
    void testGettingAttributeByFqn() throws IOException {
        AttributesServiceGrpc.AttributesServiceImplBase attributesService = new AttributesServiceGrpc.AttributesServiceImplBase() {
            @Override
            public void getAttributeValuesByFqns(GetAttributeValuesByFqnsRequest request,
            io.grpc.stub.StreamObserver<GetAttributeValuesByFqnsResponse> responseObserver) {
                Attribute attribute1 = Attribute.newBuilder().setId("CLS").setNamespace(
                    Namespace.newBuilder().setId("v").setName("virtru.com").setFqn("https://virtru.com").build())
                    .setName("Classification").setRule(AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY).setFqn("https://virtru.com/attr/classification").build();

                Value attributeValue1 = Value.newBuilder()
                .setValue("value1")
                .build();

                // Create a sample AttributeValues object
                AttributeAndValue attributeAndValues = AttributeAndValue.newBuilder().setAttribute(attribute1)
                        .setValue(attributeValue1)
                        .build();
                GetAttributeValuesByFqnsResponse response =  GetAttributeValuesByFqnsResponse.newBuilder()
                .putFqnAttributeValues("https://virtru.com/attr/classification/value/value1",attributeAndValues)
                .build();
                responseObserver.onNext(response);
                responseObserver.onCompleted();

            }
        };

        Server attrServer = null;
        try {
            attrServer = startServer(attributesService);
            String attrServerUrl = "localhost:" + attrServer.getPort();
            ManagedChannel channel = ManagedChannelBuilder
                    .forTarget(attrServerUrl)
                    .usePlaintext()
                    .build();
            try (var attr = new AttributesClient(channel)) {
                GetAttributeValuesByFqnsResponse resp = attr.getAttributeValuesByFqn(GetAttributeValuesByFqnsRequest.newBuilder().build());
                Set<String> fqnSet = new HashSet<>(Arrays.asList("https://virtru.com/attr/classification/value/value1"));
                assertThat(resp.getFqnAttributeValuesMap().keySet()).isEqualTo(fqnSet);
                assertThat(resp.getFqnAttributeValuesCount()).isEqualTo(1);
            }
        } finally {
            if (attrServer != null) {
                attrServer.shutdownNow();
            }
        }
    }
    private static Server startServer(AttributesServiceGrpc.AttributesServiceImplBase attrService) throws IOException {
        return ServerBuilder
                .forPort(getRandomPort())
                .directExecutor()
                .addService(attrService)
                .build()
                .start();
    }
    
}
