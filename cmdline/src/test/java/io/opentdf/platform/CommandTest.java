package io.opentdf.platform;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;

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
        assertThat(out.lines()).containsExactlyInAnyOrder("dpop", "dpop_nonce_challenge");
    }

    @Test
    void supports_noArgs_json_listsFeatures() {
        int[] code = new int[1];
        String out = captureStdout(() -> code[0] = new CommandLine(new Command()).execute("supports", "--json"));

        assertThat(code[0]).isEqualTo(0);
        assertThat(out.trim()).isEqualTo("{\"dpop\":true,\"dpop_nonce_challenge\":true}");
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

}
