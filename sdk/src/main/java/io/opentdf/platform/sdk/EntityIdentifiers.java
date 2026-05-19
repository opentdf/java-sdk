package io.opentdf.platform.sdk;

import io.opentdf.platform.authorization.v2.EntityIdentifier;
import io.opentdf.platform.entity.Entity;
import io.opentdf.platform.entity.EntityChain;
import io.opentdf.platform.entity.Token;

import java.util.Objects;

/**
 * Convenience constructors for {@link EntityIdentifier}, mirroring the Go SDK helpers
 * in {@code authorization/v2.ForEmail}, {@code ForClientID}, etc.
 *
 * <p>Each method builds the full {@code EntityIdentifier} proto so callers avoid
 * deeply nested builder chains.
 *
 * <pre>{@code
 * // Before
 * EntityIdentifier.newBuilder()
 *     .setEntityChain(EntityChain.newBuilder()
 *         .addEntities(Entity.newBuilder()
 *             .setEmailAddress("jen@example.com")
 *             .setCategory(Entity.Category.CATEGORY_SUBJECT)))
 *     .build();
 *
 * // After
 * EntityIdentifiers.forEmail("jen@example.com");
 * }</pre>
 */
final class EntityIdentifiers {

    private EntityIdentifiers() {}

    /**
     * Returns an EntityIdentifier for a subject identified by email address.
     */
    public static EntityIdentifier forEmail(String email) {
        Objects.requireNonNull(email, "email must not be null");
        return fromEntity(Entity.newBuilder()
                .setEmailAddress(email)
                .setCategory(Entity.Category.CATEGORY_SUBJECT)
                .build());
    }

    /**
     * Returns an EntityIdentifier for a subject identified by client ID.
     */
    public static EntityIdentifier forClientId(String clientId) {
        Objects.requireNonNull(clientId, "clientId must not be null");
        return fromEntity(Entity.newBuilder()
                .setClientId(clientId)
                .setCategory(Entity.Category.CATEGORY_SUBJECT)
                .build());
    }

    /**
     * Returns an EntityIdentifier for a subject identified by username.
     */
    public static EntityIdentifier forUserName(String userName) {
        Objects.requireNonNull(userName, "userName must not be null");
        return fromEntity(Entity.newBuilder()
                .setUserName(userName)
                .setCategory(Entity.Category.CATEGORY_SUBJECT)
                .build());
    }

    /**
     * Returns an EntityIdentifier that resolves the entity from the given JWT.
     * The authorization service parses the token to derive the entity chain.
     */
    public static EntityIdentifier forToken(String jwt) {
        Objects.requireNonNull(jwt, "jwt must not be null");
        return EntityIdentifier.newBuilder()
                .setToken(Token.newBuilder().setJwt(jwt).build())
                .build();
    }

    private static EntityIdentifier fromEntity(Entity entity) {
        return EntityIdentifier.newBuilder()
                .setEntityChain(EntityChain.newBuilder()
                        .addEntities(entity)
                        .build())
                .build();
    }
}
