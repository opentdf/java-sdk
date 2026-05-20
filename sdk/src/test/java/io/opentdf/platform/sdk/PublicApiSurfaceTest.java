package io.opentdf.platform.sdk;

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaConstructor;
import com.tngtech.archunit.core.domain.JavaField;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.core.domain.JavaType;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Enforces that every public type in {@code io.opentdf.platform.sdk} is reachable
 * from the SDK's published API surface (the {@link #API_ROOTS}). A type that is
 * not reachable should either be made package-private or wired through one of
 * the roots so callers can actually use it.
 *
 * Conversely, every type that is exposed via an API ROOT should be public so that
 * clients can refer to it.
 *
 * <p>Reachability follows the declared API surface only — superclass and
 * interfaces, public/protected methods (return type, parameters, declared
 * exceptions), public/protected constructors, public/protected fields, and
 * public/protected nested classes. Method bodies are NOT traversed; internal
 * implementation references do not count as exposure.
 */
class PublicApiSurfaceTest {

    private static final String SDK_PACKAGE = "io.opentdf.platform.sdk";

    private static final Set<String> API_ROOTS = Set.of(
            SDK.class.getName(),
            SDKBuilder.class.getName(),
            AssertionConfig.class.getName(),
            Config.class.getName(),
            RequestHelper.class.getName(),
            PolicyEnums.class.getName()
    );
    static Set<JavaClass> reachableClasses;
    static JavaClasses apiClasses;

    @BeforeAll
    static void init() {
        apiClasses = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages(SDK_PACKAGE);

        reachableClasses = computeReachable(apiClasses);
    }

    @Test
    void onlyReachableTypesAreExposed() {

        Set<String> publicButNotReachable = apiClasses.stream()
                .filter(c -> SDK_PACKAGE.equals(c.getPackageName()))
                .filter(c -> !c.isAssignableTo(SDKException.class))
                .filter(c -> isExposed(c.getModifiers()))
                .filter(c -> !c.isAnonymousClass() && !c.isLocalClass())
                .filter(c -> !c.getSimpleName().equals("package-info"))
                .filter(c -> !reachableClasses.contains(c))

                .map(JavaClass::getName)
                .collect(Collectors.toCollection(TreeSet::new));

        assertThat(publicButNotReachable)
                .as("Only types reachable from %s should be public. "
                                + "Either reduce visibility (package-private) or expose them via an API root.",
                        API_ROOTS)
                .isEmpty();
    }

    @Test
    public void allReachableTypesAreExposed() {
        Set<String> reachableButNotPublic = apiClasses.stream()
                .filter(c -> SDK_PACKAGE.equals(c.getPackageName()))
                .filter(c -> !isExposed(c.getModifiers()))
                .filter(c -> !c.isAnonymousClass() && !c.isLocalClass())
                .filter(c -> !c.getSimpleName().equals("package-info"))
                .filter(c -> reachableClasses.contains(c))

                .map(JavaClass::getName)
                .collect(Collectors.toCollection(TreeSet::new));

        assertThat(reachableButNotPublic)
                .as("All types reachable from %s should be public. "
                                + "Either increase visibility (public) or make sure they are not exposed from an API Root.",
                        API_ROOTS)
                .isEmpty();

    }

    private static Set<JavaClass> computeReachable(JavaClasses classes) {
        Set<JavaClass> reachable = new HashSet<>();
        Set<JavaClass> queued = new HashSet<>();
        Deque<JavaClass> work = new ArrayDeque<>();
        for (String root : API_ROOTS) {
            work.push(classes.get(root));
        }

        while (!work.isEmpty()) {
            JavaClass c = work.pop();
            if (!reachable.add(c)) continue;

            // Superclass and interfaces are part of the API surface of c.
            c.getRawSuperclass().ifPresent(ec -> addAllRawTypes(c, work, queued));
            work.addAll(c.getRawInterfaces());

            // if you are exposed then your enclosing class should be as well
            c.getEnclosingClass().ifPresent(ec -> addAllRawTypes(ec, work, queued));

            for (JavaMethod m : c.getMethods()) {
                if (!isExposed(m.getModifiers())) continue;
                addAllRawTypes(m.getReturnType(), work, queued);
                m.getParameterTypes().forEach(t -> addAllRawTypes(t, work, queued));
                m.getExceptionTypes().forEach(t -> addAllRawTypes(t, work, queued));
            }
            for (JavaConstructor ctor : c.getConstructors()) {
                if (!isExposed(ctor.getModifiers())) continue;
                addAllRawTypes(ctor.getReturnType(), work, queued);
                ctor.getParameterTypes().forEach(t -> addAllRawTypes(t, work, queued));
                ctor.getExceptionTypes().forEach(t -> addAllRawTypes(t, work, queued));
            }
            for (JavaField f : c.getFields()) {
                if (!isExposed(f.getModifiers())) continue;
                addAllRawTypes(f.getType(), work, queued);
            }
        }
        return reachable;
    }

    private static void addAllRawTypes(JavaType javaType, Deque<JavaClass> work, Set<JavaClass> queued) {
        for (JavaClass rt : javaType.getAllInvolvedRawTypes()) {
            if (!queued.contains(rt)) {
                work.push(rt);
                queued.add(rt);
            }
        }
    }

    private static boolean isExposed(Set<JavaModifier> mods) {
        return mods.contains(JavaModifier.PUBLIC) || mods.contains(JavaModifier.PROTECTED);
    }
}
