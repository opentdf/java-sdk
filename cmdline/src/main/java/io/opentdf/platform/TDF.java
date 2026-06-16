package io.opentdf.platform;

import picocli.CommandLine;

public class TDF {
    public static void main(String[] args) {
        var command = new Command();
        var cmd = new CommandLine(command);
        cmd.setExecutionExceptionHandler((ex, commandLine, parseResult) -> {
            if (command.verbose) {
                ex.printStackTrace(System.err);
            } else {
                System.err.println(ex.getMessage() != null ? ex.getMessage() : ex.toString());
            }
            return 1;
        });
        System.exit(cmd.execute(args));
    }
}