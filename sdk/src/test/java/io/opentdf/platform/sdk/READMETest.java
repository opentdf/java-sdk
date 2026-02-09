package io.opentdf.platform.sdk;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * READMETest verifies that Java code blocks in the README are syntactically valid.
 * This ensures the documentation stays accurate and up-to-date with the actual API.
 */
public class READMETest {

    @Test
    public void testREADMECodeBlocks() throws IOException {
        // Read the README file
        Path readmePath = Path.of("..").resolve("README.md").toAbsolutePath().normalize();
        String content = Files.readString(readmePath);

        // Extract Java code blocks
        List<String> codeBlocks = extractJavaCodeBlocks(content);
        assertTrue(codeBlocks.size() > 0, "No Java code blocks found in README.md");

        System.out.println("Found " + codeBlocks.size() + " Java code block(s) in README.md");

        // Test each code block that is a complete program
        int testedCount = 0;
        for (int i = 0; i < codeBlocks.size(); i++) {
            String code = codeBlocks.get(i);

            // Only test complete programs (those with package and main method)
            if (!code.contains("package ") || !code.contains("public static void main")) {
                System.out.println("Skipping code block " + (i + 1) + " (not a complete program)");
                continue;
            }

            testedCount++;
            System.out.println("Testing code block " + (i + 1));

            try {
                validateCodeBlock(code, i + 1);
                System.out.println("Code block " + (i + 1) + " validated successfully");
            } catch (AssertionError e) {
                fail("Code block " + (i + 1) + " validation failed: " + e.getMessage());
            }
        }

        assertTrue(testedCount > 0, "No complete program code blocks found in README.md");
        System.out.println("Validated " + testedCount + " complete program(s)");
    }

    /**
     * Extracts all Java code blocks from the markdown content.
     */
    private List<String> extractJavaCodeBlocks(String content) {
        List<String> blocks = new ArrayList<>();
        Pattern pattern = Pattern.compile("```java\\n(.*?)```", Pattern.DOTALL);
        Matcher matcher = pattern.matcher(content);

        while (matcher.find()) {
            blocks.add(matcher.group(1));
        }

        return blocks;
    }

    /**
     * Validates that a code block has proper structure and imports.
     */
    private void validateCodeBlock(String code, int blockNumber) {
        // Check for required imports that should be present
        assertTrue(code.contains("import io.opentdf.platform.sdk.SDK"),
                "Block " + blockNumber + ": Missing SDK import");
        assertTrue(code.contains("import io.opentdf.platform.sdk.SDKBuilder"),
                "Block " + blockNumber + ": Missing SDKBuilder import");
        assertTrue(code.contains("import io.opentdf.platform.sdk.Config"),
                "Block " + blockNumber + ": Missing Config import");

        // Check that Reader is imported as TDF not as standalone Reader
        assertFalse(code.contains("import io.opentdf.platform.sdk.Reader"),
                "Block " + blockNumber + ": Should not import non-existent Reader class. Use TDF.Reader instead.");

        // Check for proper TDF.Reader usage (not just Reader)
        if (code.contains("Reader reader")) {
            assertTrue(code.contains("TDF.Reader reader") || code.contains("import io.opentdf.platform.sdk.TDF"),
                    "Block " + blockNumber + ": Should use TDF.Reader, not Reader");
        }

        // Check for correct API usage
        if (code.contains("loadTDF")) {
            assertTrue(code.contains("sdk.loadTDF"),
                    "Block " + blockNumber + ": loadTDF should be called on SDK instance");
        }

        if (code.contains("createTDF")) {
            assertTrue(code.contains("sdk.createTDF"),
                    "Block " + blockNumber + ": createTDF should be called on SDK instance");
        }

        // Check for proper class structure
        assertTrue(code.contains("public class"),
                "Block " + blockNumber + ": Should contain a public class");
        assertTrue(code.contains("public static void main(String[] args)") ||
                        code.contains("public static void main(String...args)"),
                "Block " + blockNumber + ": Should contain a main method");

        // Check for proper exception handling
        assertTrue(code.contains("throws") || code.contains("try"),
                "Block " + blockNumber + ": Should handle exceptions (throws or try-catch)");

        // Validate matching braces
        long openBraces = code.chars().filter(ch -> ch == '{').count();
        long closeBraces = code.chars().filter(ch -> ch == '}').count();
        assertEquals(openBraces, closeBraces,
                "Block " + blockNumber + ": Mismatched braces");

        // Validate matching parentheses
        long openParens = code.chars().filter(ch -> ch == '(').count();
        long closeParens = code.chars().filter(ch -> ch == ')').count();
        assertEquals(openParens, closeParens,
                "Block " + blockNumber + ": Mismatched parentheses");

        System.out.println("  ✓ All validation checks passed");
    }
}

