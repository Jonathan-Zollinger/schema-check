package com.schemacheck.cmd;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Paths;

class SchemaCheckTest {
    String testResourcesDir = String.join(String.valueOf(File.separatorChar), "src/test/resources".split("/"));
    SchemaCheck schemaCheck;

    @BeforeEach
    void setUp() {
        System.setProperty("com.sun.jndi.ldap.object.disableEndpointIdentification","true");
        schemaCheck = new SchemaCheck();
    }

    @AfterEach
    void tearDown() {
        System.setProperty("com.sun.jndi.ldap.object.disableEndpointIdentification","false");
    }

    void readEnv() {
        schemaCheck.envFile = Paths.get(testResourcesDir +File.separatorChar + ".env");
    }
    @Test
    void tireKick() {
        readEnv();
        schemaCheck.directory = Paths.get(testResourcesDir + File.separatorChar + "original-test-data");
        schemaCheck.run();
    }
}