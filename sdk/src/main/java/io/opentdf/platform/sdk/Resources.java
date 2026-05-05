package io.opentdf.platform.sdk;

import io.opentdf.platform.authorization.v2.Resource;

import java.util.Arrays;
import java.util.Objects;

/**
 * Convenience constructors for {@link Resource}, analogous to the
 * {@link EntityIdentifiers} helpers for {@link io.opentdf.platform.authorization.v2.EntityIdentifier}.
 *
 * <p>Each method builds the full {@code Resource} proto so callers avoid
 * deeply nested builder chains.
 *
 * <pre>{@code
 * // Before
 * Resource.newBuilder()
 *     .setAttributeValues(
 *         Resource.AttributeValues.newBuilder()
 *             .addFqns("https://example.com/attr/department/value/finance"))
 *     .build();
 *
 * // After
 * Resources.forAttributeValues("https://example.com/attr/department/value/finance");
 * }</pre>
 */
public final class Resources {

    private Resources() {}

    /**
     * Returns a Resource containing the given attribute value FQNs.
     * This is the most common Resource variant, used when authorizing against
     * attribute values attached to data (e.g. those on a TDF).
     *
     * @param fqns one or more fully qualified attribute value names
     * @return a fully built {@link Resource} with the {@code attribute_values} oneof set
     * @throws NullPointerException if {@code fqns} or any element is null
     * @throws IllegalArgumentException if {@code fqns} is empty
     */
    public static Resource forAttributeValues(String... fqns) {
        Objects.requireNonNull(fqns, "fqns must not be null");
        if (fqns.length == 0) {
            throw new IllegalArgumentException("fqns must not be empty");
        }
        for (String fqn : fqns) {
            Objects.requireNonNull(fqn, "individual fqn must not be null");
        }
        return Resource.newBuilder()
                .setAttributeValues(
                        Resource.AttributeValues.newBuilder()
                                .addAllFqns(Arrays.asList(fqns))
                                .build())
                .build();
    }

    /**
     * Returns a Resource that references a single registered resource value
     * by its fully qualified name, as stored in platform policy.
     *
     * @param fqn the fully qualified name of the registered resource value
     * @return a fully built {@link Resource} with the {@code registered_resource_value_fqn} oneof set
     * @throws NullPointerException if {@code fqn} is null
     */
    public static Resource forRegisteredResourceValueFqn(String fqn) {
        Objects.requireNonNull(fqn, "fqn must not be null");
        return Resource.newBuilder()
                .setRegisteredResourceValueFqn(fqn)
                .build();
    }
}
