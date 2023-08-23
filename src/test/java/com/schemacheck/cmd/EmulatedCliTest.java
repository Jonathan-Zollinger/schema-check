package com.schemacheck.cmd;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EmulatedCliTest {
    final PrintStream originalOut = System.out;
    final PrintStream originalErr = System.err;
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    static CommandLine cmd;

    @BeforeEach
    void setUp(){
        out.reset();
        err.reset();
        System.setOut(new PrintStream(out));
        System.setErr(new PrintStream(err));
        cmd = new CommandLine(new SchemaCheck());
    }

    @AfterEach
    void tearDown(){
        System.setOut(originalOut);
        System.setErr(originalErr);
    }

    @Test
    public void trustAllCertsFlag() {
        String noTrustStoreFile = String.join(File.separator, "src/test/resources/no-trust-store".split("/"));
        String testsDirectory = String.join(File.separator, "src/test/resources/original-test-data".split("/"));
        cmd.execute(String.format("--cheat --env %s --dir %s", noTrustStoreFile, testsDirectory).split(" "));
        assertEquals("", err.toString());
    }

    @Test
    public void badDirArg() {
        cmd.execute();
        assertTrue(err.toString().startsWith("No tests found in the \u001B[33m"));
    }

    @Test
    public void version() {
        cmd.execute("--cheat");
        assertEquals("", err.toString());
    }


}
