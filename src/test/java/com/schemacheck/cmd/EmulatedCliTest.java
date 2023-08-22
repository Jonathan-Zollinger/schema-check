package com.schemacheck.cmd;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
        cmd.execute("--cheat");
        assertEquals("", err.toString());
    }


}