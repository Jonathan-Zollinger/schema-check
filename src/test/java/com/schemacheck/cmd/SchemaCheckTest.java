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
        schemaCheck.directory = Paths.get(testResourcesDir + File.separatorChar + "original-test-data");
    }

    @AfterEach
    void tearDown() {
        System.setProperty("com.sun.jndi.ldap.object.disableEndpointIdentification","false");
    }

    void readEnv(String fileName) {
        schemaCheck.envFile = Paths.get(testResourcesDir +File.separatorChar + fileName);
    }
    @Test
    void tireKick() {
        readEnv(".env");
        schemaCheck.run();
    }

    @Test
    void trustAllCerts() {
        readEnv("no-trust-store");
        schemaCheck.trustAllCerts = true;
        schemaCheck.run();
    }
}