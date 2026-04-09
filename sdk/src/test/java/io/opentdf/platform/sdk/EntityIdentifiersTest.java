package io.opentdf.platform.sdk;

import static org.junit.jupiter.api.Assertions.*;

import io.opentdf.platform.authorization.v2.EntityIdentifier;
import io.opentdf.platform.entity.Entity;
import io.opentdf.platform.entity.EntityChain;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class EntityIdentifiersTest {

    @ParameterizedTest
    @ValueSource(strings = {"user@example.com", ""})
    void forEmail(String email) {
        EntityIdentifier eid = EntityIdentifiers.forEmail(email);

        EntityChain chain = extractEntityChain(eid);
        assertEquals(1, chain.getEntitiesCount());

        Entity e = chain.getEntities(0);
        assertEquals(Entity.EntityTypeCase.EMAIL_ADDRESS, e.getEntityTypeCase());
        assertEquals(email, e.getEmailAddress());
        assertEquals(Entity.Category.CATEGORY_SUBJECT, e.getCategory());
    }

    @ParameterizedTest
    @ValueSource(strings = {"my-client", ""})
    void forClientId(String clientId) {
        EntityIdentifier eid = EntityIdentifiers.forClientId(clientId);

        EntityChain chain = extractEntityChain(eid);
        assertEquals(1, chain.getEntitiesCount());

        Entity e = chain.getEntities(0);
        assertEquals(Entity.EntityTypeCase.CLIENT_ID, e.getEntityTypeCase());
        assertEquals(clientId, e.getClientId());
        assertEquals(Entity.Category.CATEGORY_SUBJECT, e.getCategory());
    }

    @ParameterizedTest
    @ValueSource(strings = {"alice", ""})
    void forUserName(String userName) {
        EntityIdentifier eid = EntityIdentifiers.forUserName(userName);

        EntityChain chain = extractEntityChain(eid);
        assertEquals(1, chain.getEntitiesCount());

        Entity e = chain.getEntities(0);
        assertEquals(Entity.EntityTypeCase.USER_NAME, e.getEntityTypeCase());
        assertEquals(userName, e.getUserName());
        assertEquals(Entity.Category.CATEGORY_SUBJECT, e.getCategory());
    }

    @ParameterizedTest
    @ValueSource(strings = {"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test", ""})
    void forToken(String jwt) {
        EntityIdentifier eid = EntityIdentifiers.forToken(jwt);

        assertEquals(EntityIdentifier.IdentifierCase.TOKEN, eid.getIdentifierCase());
        assertEquals(jwt, eid.getToken().getJwt());
    }

    @Test
    void nullInputsThrow() {
        assertThrows(NullPointerException.class, () -> EntityIdentifiers.forEmail(null));
        assertThrows(NullPointerException.class, () -> EntityIdentifiers.forClientId(null));
        assertThrows(NullPointerException.class, () -> EntityIdentifiers.forUserName(null));
        assertThrows(NullPointerException.class, () -> EntityIdentifiers.forToken(null));
    }

    private static EntityChain extractEntityChain(EntityIdentifier eid) {
        assertEquals(EntityIdentifier.IdentifierCase.ENTITY_CHAIN, eid.getIdentifierCase(),
                "expected ENTITY_CHAIN identifier");
        return eid.getEntityChain();
    }
}
