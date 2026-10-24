package io.opentdf.platform;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.opentdf.platform.sdk.ZipWriter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class CommandTest {

    private final PrintStream originalOut = System.out;

    @AfterEach
    void restoreStdout() {
        System.setOut(originalOut);
    }

    private String captureStdout(Runnable action) {
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        System.setOut(new PrintStream(captured, true, StandardCharsets.UTF_8));
        try {
            action.run();
        } finally {
            System.setOut(originalOut);
        }
        return captured.toString(StandardCharsets.UTF_8);
    }

    @Test
    void supports_dpop_exits_0() {
        int code = new CommandLine(new Command()).execute("supports", "dpop");
        assertThat(code).isEqualTo(0);
    }

    @Test
    void supports_dpop_nonce_challenge_exits_0() {
        int code = new CommandLine(new Command()).execute("supports", "dpop_nonce_challenge");
        assertThat(code).isEqualTo(0);
    }

    @Test
    void supports_unknown_feature_exits_1() {
        int code = new CommandLine(new Command()).execute("supports", "unknown_feature");
        assertThat(code).isEqualTo(1);
    }

    @Test
    void encrypt_withoutCredentials_failsWithMissingPlatformEndpoint() {
        StringWriter err = new StringWriter();
        CommandLine cli = new CommandLine(new Command());
        cli.setErr(new PrintWriter(err));

        int code = cli.execute("encrypt", "-k", "https://kas.example.com", "-f", "/dev/null");

        // Picocli exit code for ParameterException is USAGE (2).
        assertThat(code).isEqualTo(CommandLine.ExitCode.USAGE);
        assertThat(err.toString()).contains("Missing required option: '--platform-endpoint=<platformEndpoint>'");
    }

    @Test
    void supports_withoutCredentials_stillExits0() {
        // Regression sentinel: tdf supports must not require --client-id/--client-secret/--platform-endpoint.
        int code = new CommandLine(new Command()).execute("supports", "dpop");
        assertThat(code).isEqualTo(0);
    }

    @Test
    void verbose_flag_accepted_by_supports() {
        int code = new CommandLine(new Command()).execute("--verbose", "supports", "dpop");
        assertThat(code).isEqualTo(0);
    }

    @Test
    void verbose_short_flag_accepted_by_supports() {
        int code = new CommandLine(new Command()).execute("-v", "supports", "dpop");
        assertThat(code).isEqualTo(0);
    }

    @Test
    void verbose_flag_sets_verbose_field() {
        var command = new Command();
        new CommandLine(command).parseArgs("--verbose", "supports", "dpop");
        assertThat(command.verbose).isTrue();
    }

    @Test
    void supports_noArgs_listsFeatures_exits0() {
        int[] code = new int[1];
        String out = captureStdout(() -> code[0] = new CommandLine(new Command()).execute("supports"));

        assertThat(code[0]).isEqualTo(0);
        assertThat(out.lines()).containsExactlyInAnyOrder("dpop", "dpop_nonce_challenge", "tdf_validity");
    }

    @Test
    void supports_noArgs_json_listsFeatures() {
        int[] code = new int[1];
        String out = captureStdout(() -> code[0] = new CommandLine(new Command()).execute("supports", "--json"));

        assertThat(code[0]).isEqualTo(0);
        assertThat(out.trim()).isEqualTo("{\"dpop\":true,\"dpop_nonce_challenge\":true,\"tdf_validity\":true}");
    }

    @Test
    void supports_feature_json_true() {
        int[] code = new int[1];
        String out = captureStdout(() -> code[0] = new CommandLine(new Command()).execute("supports", "dpop", "--json"));

        assertThat(code[0]).isEqualTo(0);
        assertThat(out.trim()).isEqualTo("{\"dpop\":true}");
    }

    @Test
    void supports_feature_json_emitsCanonicalName() {
        // A recognized feature given with non-canonical casing must serialize under the
        // canonical key so JSON output is stable for automation.
        int[] code = new int[1];
        String out = captureStdout(() -> code[0] = new CommandLine(new Command()).execute("supports", "DPoP", "--json"));

        assertThat(code[0]).isEqualTo(0);
        assertThat(out.trim()).isEqualTo("{\"dpop\":true}");
    }

    @Test
    void supports_unknownFeature_json_false() {
        int[] code = new int[1];
        String out = captureStdout(
                () -> code[0] = new CommandLine(new Command()).execute("supports", "unknown_feature", "--json"));

        assertThat(code[0]).isEqualTo(1);
        assertThat(out.trim()).isEqualTo("{\"unknown_feature\":false}");
    }

    @Test
    void supports_tdf_validity_exits_0() {
        int code = new CommandLine(new Command()).execute("supports", "tdf_validity");
        assertThat(code).isEqualTo(0);
    }

    private static final String MINIMAL_MANIFEST = "{\"payload\":{\"type\":\"reference\",\"url\":\"0.payload\","
            + "\"protocol\":\"zip\",\"isEncrypted\":true},\"encryptionInformation\":{}}";

    @TempDir
    Path tempDir;

    private Path tdfWithManifest(String manifest) throws IOException {
        var out = new ByteArrayOutputStream();
        var zip = new ZipWriter(out);
        zip.data("0.payload", new byte[16]);
        zip.data("0.manifest.json", manifest.getBytes(StandardCharsets.UTF_8));
        zip.finish();
        return Files.write(Files.createTempFile(tempDir, "validate", ".tdf"), out.toByteArray());
    }

    /** Runs {@code validate} the way the jar does, without platform options, and returns stdout. */
    private String validate(int[] code, String... args) {
        String[] command = new String[args.length + 1];
        command[0] = "validate";
        System.arraycopy(args, 0, command, 1, args.length);
        return captureStdout(() -> code[0] = new CommandLine(new Command()).execute(command));
    }

    @Test
    void validate_validTdf_printsValidAndExits0() throws IOException {
        int[] code = new int[1];
        String out = validate(code, tdfWithManifest(MINIMAL_MANIFEST).toString());

        assertThat(code[0]).isEqualTo(0);
        assertThat(out).isEqualTo("{\"valid\":true}" + System.lineSeparator());
    }

    @Test
    void validate_invalidManifest_printsReasonAndExits3() throws IOException {
        int[] code = new int[1];
        String out = validate(code, tdfWithManifest("{\"encryptionInformation\":{}}").toString());

        assertThat(code[0]).isEqualTo(3);
        assertThat(out.lines()).hasSize(1);
        JsonObject result = JsonParser.parseString(out).getAsJsonObject();
        assertThat(result.keySet()).containsExactly("valid", "reason");
        assertThat(result.get("valid").getAsBoolean()).isFalse();
        assertThat(result.get("reason").getAsString()).contains("lax manifest schema");
    }

    @Test
    void validate_fileThatIsNotAZip_exits3() throws IOException {
        int[] code = new int[1];
        Path notAZip = Files.writeString(tempDir.resolve("not-a-zip"), MINIMAL_MANIFEST);
        String out = validate(code, notAZip.toString());

        assertThat(code[0]).isEqualTo(3);
        assertThat(JsonParser.parseString(out).getAsJsonObject().get("valid").getAsBoolean()).isFalse();
    }

    @Test
    void validate_emptyFile_exits3() throws IOException {
        int[] code = new int[1];
        String out = validate(code, Files.createFile(tempDir.resolve("empty")).toString());

        assertThat(code[0]).isEqualTo(3);
        assertThat(JsonParser.parseString(out).getAsJsonObject().get("valid").getAsBoolean()).isFalse();
    }

    /** A reason with quotes, angle brackets and the like is still one line of JSON. */
    @Test
    void validate_reasonIsEscapedJson() throws IOException {
        int[] code = new int[1];
        String out = validate(code, tdfWithManifest("{\"<'quoted'>\": \"\\u0022\"").toString());

        assertThat(code[0]).isEqualTo(3);
        assertThat(out.lines()).hasSize(1);
        assertThat(JsonParser.parseString(out).getAsJsonObject().get("reason").getAsString())
                .startsWith("manifest is not valid JSON");
    }

    /** A file that can't be read is not an invalid TDF: the check didn't run. */
    @Test
    void validate_missingFile_exitsWithAnotherCodeAndPrintsNothing() {
        int[] code = new int[1];
        StringWriter err = new StringWriter();
        String out = captureStdout(() -> {
            CommandLine cli = new CommandLine(new Command());
            cli.setErr(new PrintWriter(err));
            code[0] = cli.execute("validate", tempDir.resolve("does-not-exist.tdf").toString());
        });

        assertThat(code[0]).isNotIn(0, 3);
        assertThat(code[0]).isEqualTo(CommandLine.ExitCode.SOFTWARE);
        assertThat(out).isEmpty();
    }

    @Test
    void validate_withoutAFile_isAUsageError() {
        int[] code = new int[1];
        StringWriter err = new StringWriter();
        String out = captureStdout(() -> {
            CommandLine cli = new CommandLine(new Command());
            cli.setErr(new PrintWriter(err));
            code[0] = cli.execute("validate");
        });

        assertThat(code[0]).isEqualTo(CommandLine.ExitCode.USAGE);
        assertThat(out).isEmpty();
        assertThat(err.toString()).contains("Missing required parameter: '<file>'");
    }

}
