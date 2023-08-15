package com.schemacheck.cmd;

import com.schemacheck.model.IdmUnitTest;
import com.schemacheck.util.JsonUtils;
import com.schemacheck.util.LdapUtils;
import com.schemacheck.util.PicoCliValidation;
import org.fusesource.jansi.AnsiConsole;
import picocli.CommandLine;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.ldap.InitialLdapContext;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@CommandLine.Command(name = "schema-check",
        description = "validates an IdmUnit json test schema against a directory service.",
        mixinStandardHelpOptions = true,
        versionProvider = SchemaCheck.ManifestVersionProvider.class,
        showDefaultValues = true)
public class SchemaCheck implements Runnable {

    String IP, ADMIN_DN, ADMIN_SECRET, TRUST_STORE, TRUST_STORE_PASSWORD, SSL_PORT;
    @CommandLine.Spec
    CommandLine.Model.CommandSpec spec;

    DirContext context;
    LdapUtils ldapUtils;

    @CommandLine.Option(
            names = "--dir",
            description = "directory of idmTests to be validated."
    )
    Path directory;

    @CommandLine.Option(
            names = "--env",
            description = "environment variables with which to access eDirectory",
            defaultValue = ".env"
    )
    Path envFile;

    public static void main(String[] args) {
        // To avoid warnings about Log42 not being in classpath
        // See https://poi.apache.org/components/logging.html for more information (Specifically the Log4J SimpleLogger section)
        System.getProperties().setProperty("log4j2.loggerContextFactory", "org.apache.logging.log4j.simple.SimpleLoggerContextFactory");

        AnsiConsole.systemInstall();
        CommandLine cmd = new CommandLine(new SchemaCheck());
        int exitCode = cmd.execute(args);
        AnsiConsole.systemUninstall();
        System.exit(exitCode);
    }

    @Override
    public void run() {
        initiateLdapConnection();
        try (PrintWriter logWriter = new PrintWriter(Files.newOutputStream(
                Paths.get(directory.toString() + File.separatorChar + directory.getFileName().toString() + ".log")))) {
        for (Path testPath : getFilePaths()) {
            IdmUnitTest idmUnitTest = getTest(testPath);

                logWriter.println("["  + idmUnitTest.getName() + "]");
                idmUnitTest.getOperations().forEach(operation -> {
                    logWriter.println("\t--[" + operation.getComment() + "]");
                    if (null == operation.getData() || operation.getData().isEmpty()){
                        logWriter.println("\t\t[WARNING] This operation has no data.");
                        return;
                    }
                    Set<String> missingAttributes = ldapUtils.getMissingRequiredAttributeNames(operation);
                    if (null != missingAttributes && !missingAttributes.isEmpty()) {
                        String lineRunner = "\t\t[WARNING] [MISSING ATTRIBUTE] \"";
                        logWriter.println(lineRunner + String.join("\"" + System.lineSeparator() + lineRunner, missingAttributes));
                    }else {
                        logWriter.println("\t\t[INFO] This operation is not missing any required attributes");
                    }
                });
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }


    }

    private IdmUnitTest getTest(Path testPath) {
        IdmUnitTest idmUnitTest;
        try (InputStream testStream = Files.newInputStream(testPath)) {
            idmUnitTest = JsonUtils.getMapper().readValue(testStream, IdmUnitTest.class);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read from " + testPath, e);
        }
        return idmUnitTest;
    }


    void getEnv() {
        PicoCliValidation.fileExistsAndIsReadable(spec, envFile);
        ResourceBundle envProperties;
        try (FileInputStream propertiesStream = new FileInputStream(envFile.toFile())) {
            envProperties = new PropertyResourceBundle(propertiesStream);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        List<String> missingProperties = Stream.of("ADMIN_DN", "ADMIN_SECRET", "TRUST_STORE", "TRUST_STORE_PASSWORD", "SSL_PORT", "IP")
                .filter(property -> !envProperties.containsKey(property)).collect(Collectors.toList());
        if (!missingProperties.isEmpty()) {
            throw new IllegalStateException("The env file is missing the following properties:" +
                    "\n\t" + String.join("\n\t", missingProperties));
        }
        IP = envProperties.getString("IP");
        ADMIN_DN = envProperties.getString("ADMIN_DN");
        ADMIN_SECRET = envProperties.getString("ADMIN_SECRET");
        TRUST_STORE = envProperties.getString("TRUST_STORE");
        TRUST_STORE_PASSWORD = envProperties.getString("TRUST_STORE_PASSWORD");
        SSL_PORT = envProperties.getString("SSL_PORT");
    }

    void initiateLdapConnection() {
        getEnv();
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("com.sun.jndi.ldap.connect.pool", "true");  //CP CHANGE TO DISABLE LDAP CONNECTION POOL
        env.put("com.sun.jndi.ldap.connect.pool.protocol", "plain ssl");
        env.put("com.sun.jndi.ldap.connect.pool.timeout", "1000");
        env.put("com.sun.jndi.ldap.connect.pool.maxsize", "3");
        env.put("com.sun.jndi.ldap.connect.pool.prefsize", "1");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, ADMIN_DN);
        env.put(Context.SECURITY_CREDENTIALS, ADMIN_SECRET);
        env.put("com.sun.jndi.ldap.connect.timeout", "50000");
        env.put(Context.REFERRAL, "follow");
        env.put(Context.PROVIDER_URL, "ldaps://" + IP + ":" + SSL_PORT);
        env.put("javax.net.ssl.trustStore", TRUST_STORE);
        env.put("javax.net.ssl.trustStorePassword", TRUST_STORE_PASSWORD);
        try {
            context = new InitialLdapContext(env, null);
        } catch (NamingException e) {
            throw new RuntimeException(e);
        }
        ldapUtils = new LdapUtils(context);
    }

    List<Path> getFilePaths() {
        List<Path> testPaths;
        try (Stream<Path> files = Files.walk(directory, 1)) {
            testPaths = files
                    .filter(Files::isRegularFile)
                    .filter(path -> path.toString().endsWith(".json"))
                    .filter(path -> !path.getFileName().toString().startsWith("manifest"))
                    .sorted(Comparator.reverseOrder())
                    .collect(Collectors.toList());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return testPaths;
    }

    public static class ManifestVersionProvider implements CommandLine.IVersionProvider {
        public String[] getVersion() {
            return new String[]{SchemaCheck.class.getPackage().getImplementationVersion()};
        }
    }
}
