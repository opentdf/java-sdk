package io.opentdf.platform;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.assertj.core.api.Assertions.assertThat;

class CommandTest {

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
    void encrypt_withUnsupportedDpopAlgorithm_failsWithUsage() {
        StringWriter err = new StringWriter();
        CommandLine cli = new CommandLine(new Command());
        cli.setErr(new PrintWriter(err));

        int code = cli.execute(
                "--platform-endpoint", "https://example.invalid",
                "--client-id", "x",
                "--client-secret", "x",
                "encrypt",
                "--dpop=HS256",
                "-k", "https://kas.example.invalid",
                "-f", "/dev/null");

        assertThat(code).isEqualTo(CommandLine.ExitCode.USAGE);
        assertThat(err.toString()).contains("Unsupported DPoP algorithm").contains("HS256");
    }

    @Test
    void encrypt_withMissingDpopKeyFile_failsWithUsage() {
        StringWriter err = new StringWriter();
        CommandLine cli = new CommandLine(new Command());
        cli.setErr(new PrintWriter(err));

        int code = cli.execute(
                "--platform-endpoint", "https://example.invalid",
                "--client-id", "x",
                "--client-secret", "x",
                "encrypt",
                "--dpop-key", "/tmp/does-not-exist-dpop-key.pem",
                "-k", "https://kas.example.invalid",
                "-f", "/dev/null");

        assertThat(code).isEqualTo(CommandLine.ExitCode.USAGE);
        assertThat(err.toString()).contains("Cannot read DPoP key file")
                .contains("/tmp/does-not-exist-dpop-key.pem");
    }
}
