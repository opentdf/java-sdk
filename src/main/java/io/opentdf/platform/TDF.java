package io.opentdf.platform;

import picocli.CommandLine;

public class TDF {
    public static void main(String[] args) {
        var result = new CommandLine(new Command()).execute(args);
        System.exit(result);
    }
}