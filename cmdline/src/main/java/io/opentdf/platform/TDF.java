package io.opentdf.platform;

import picocli.CommandLine;

public class TDF {
    public static void main(String[] args) {
        try {
            var result = new CommandLine(new Command()).execute(args);
            System.exit(result);
        } catch (Throwable t) {
            // Belt-and-suspenders: picocli's default execution handler prints only
            // getMessage(), which is null for many failure modes (NPE, etc.), and
            // exceptions thrown during CommandLine construction or by picocli itself
            // bypass that handler entirely. Print the class+message (toString) plus
            // the stack trace so a failure is never silent.
            t.printStackTrace(System.err);
            System.exit(1);
        }
    }
}