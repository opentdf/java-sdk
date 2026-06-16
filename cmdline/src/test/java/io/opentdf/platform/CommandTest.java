package io.opentdf.platform;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

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
}
