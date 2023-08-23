package com.schemacheck.cmd;

import com.schemacheck.model.IdmUnitTest;
import com.schemacheck.util.JsonUtils;
import com.schemacheck.util.LdapUtils;
import com.schemacheck.util.PicoCliValidation;
import com.schemacheck.util.idmunit.IdMUnitException;
import org.fusesource.jansi.AnsiConsole;
import picocli.CommandLine;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.ldap.InitialLdapContext;
import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.fusesource.jansi.Ansi.Color.YELLOW;
import static org.fusesource.jansi.Ansi.ansi;

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
    Path directory = Paths.get(".").toAbsolutePath().getParent();

    @CommandLine.Option(
            names = "--env",
            description = "environment variables with which to access eDirectory",
            defaultValue = ".env"
    )
    Path envFile;

    @CommandLine.Option(
            names = "--cheat",
            description = "trust all certificates"
    )
    Boolean trustAllCerts;

    public static void main(String[] args) {
        CommandLine cmd = new CommandLine(new SchemaCheck());
        AnsiConsole.systemInstall();
        int exitCode = cmd.execute(args);
        AnsiConsole.systemUninstall();
        System.exit(exitCode);
    }

    @Override
    public void run() {
        if(getFilePaths().isEmpty()){
            throw new CommandLine.ParameterException(spec.commandLine(),
                    String.format("No tests found in the %s directory", ansi().fg(YELLOW).a(directory.toAbsolutePath()).reset()));
        }
        PicoCliValidation.fileExistsAndIsReadable(spec, envFile);
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
        ResourceBundle envProperties;
        try (FileInputStream propertiesStream = new FileInputStream(envFile.toFile())) {
            envProperties = new PropertyResourceBundle(propertiesStream);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        List<String> missingProperties = Stream.of("ADMIN_DN", "ADMIN_SECRET", "TRUST_STORE", "TRUST_STORE_PASSWORD", "SSL_PORT", "IP")
                .filter(property -> !envProperties.containsKey(property)).collect(Collectors.toList());
        if (null != trustAllCerts && trustAllCerts){
            missingProperties.removeAll(Arrays.asList("TRUST_STORE", "TRUST_STORE_PASSWORD"));
        }
        if (!missingProperties.isEmpty()) {
            throw new IllegalStateException("The env file is missing the following properties:" +
                    "\n\t" + String.join("\n\t", missingProperties));
        }
        try {
            IP = envProperties.getString("IP");
            ADMIN_DN = envProperties.getString("ADMIN_DN");
            ADMIN_SECRET = envProperties.getString("ADMIN_SECRET");
            if (null == trustAllCerts || !trustAllCerts) {
                TRUST_STORE = envProperties.getString("TRUST_STORE");
                TRUST_STORE_PASSWORD = envProperties.getString("TRUST_STORE_PASSWORD");
            }
            SSL_PORT = envProperties.getString("SSL_PORT");
        } catch (MissingResourceException e) {
            throw new RuntimeException(e);
        }
    }

    void initiateLdapConnection() {
        getEnv();
        Hashtable<String, String> env = new Hashtable<>();
        System.setProperty("com.sun.jndi.ldap.object.disableEndpointIdentification", "true");
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("com.sun.jndi.ldap.connect.pool", "true");
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
        if (null != trustAllCerts && trustAllCerts) {
            CustomSocketFactory.setTrustAll();
            env.put("java.naming.ldap.factory.socket", CustomSocketFactory.class.getName());
        } else {
            env.put("javax.net.ssl.trustStore", TRUST_STORE);
            env.put("javax.net.ssl.trustStorePassword", TRUST_STORE_PASSWORD);
        }

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

    public static final class CustomSocketFactory extends SocketFactory {
        private static SocketFactory factory = null;
        private static TrustManager[] tm;
        private SSLSocketFactory sf;

        private CustomSocketFactory() throws KeyManagementException, NoSuchAlgorithmException {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, tm, null);
            sf = sc.getSocketFactory();
        }

        static void setTrustAll() {
            tm = new TrustManager[] {new TrustAllX509TrustManager()};
        }

        static void setTrustedKeyStore(String keyStorePath, char[] passphrase) throws IdMUnitException {
            KeyStore caKeystore;
            try {
                caKeystore = KeyStore.getInstance(KeyStore.getDefaultType());
            } catch (KeyStoreException e) {
                throw new IdMUnitException("Error creating keystore.", e);
            }

            InputStream in;
            try {
                in = new FileInputStream(keyStorePath);
            } catch (FileNotFoundException e) {
                throw new IdMUnitException("Error reading keystore '" + keyStorePath + "'.", e);
            }
            try {
                try {
                    caKeystore.load(in, passphrase);
                } catch (NoSuchAlgorithmException e) {
                    throw new IdMUnitException("Error loading keystore '" + keyStorePath + "'.", e);
                } catch (CertificateException e) {
                    throw new IdMUnitException("Error loading keystore '" + keyStorePath + "'.", e);
                } catch (IOException e) {
                    throw new IdMUnitException("Error loading keystore '" + keyStorePath + "'.", e);
                }
            } finally {
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            setTrustManager(caKeystore);
        }

        static void setTrustedCert(String certFilePath) throws IdMUnitException {
            InputStream is;
            try {
                is = new FileInputStream(certFilePath);
            } catch (FileNotFoundException e) {
                throw new IdMUnitException("Error reading certificate '" + certFilePath + "'.", e);
            }
            try {
                CertificateFactory cf;
                try {
                    cf = CertificateFactory.getInstance("X.509");
                } catch (CertificateException e) {
                    throw new IdMUnitException("Error getting CertificateFactory.", e);
                }
                Collection<? extends Certificate> x509Certs;
                try {
                    x509Certs = cf.generateCertificates(is);
                } catch (CertificateException e) {
                    throw new IdMUnitException("Error parsing certificates '" + certFilePath + "'.", e);
                }

                KeyStore ks;
                try {
                    ks = KeyStore.getInstance(KeyStore.getDefaultType());
                } catch (KeyStoreException e) {
                    throw new IdMUnitException("Error creating KeyStore.", e);
                }

                try {
                    ks.load(null, null);
                } catch (NoSuchAlgorithmException e) {
                    throw new IdMUnitException("Error initializing KeyStore", e);
                } catch (CertificateException e) {
                    throw new IdMUnitException("Error initializing KeyStore", e);
                } catch (IOException e) {
                    throw new IdMUnitException("Error initializing KeyStore", e);
                }

                int count = 0;
                for (Iterator<? extends Certificate> it = x509Certs.iterator(); it.hasNext(); ) {
                    X509Certificate cert = (X509Certificate) it.next();
//                    cert.checkValidity();

                    String subjectPrincipal = cert.getSubjectX500Principal().toString();
                    StringTokenizer st = new StringTokenizer(subjectPrincipal, ",");
                    String cn = "";
                    while (st.hasMoreTokens()) {
                        String tok = st.nextToken();
                        int x = tok.indexOf("CN=");
                        if (x >= 0) {
                            cn = tok.substring(x + "CN=".length());
                        }
                    }
                    String alias = cn + "_" + count;
                    try {
                        ks.setCertificateEntry(alias, cert);
                    } catch (KeyStoreException e) {
                        throw new IdMUnitException("Error adding certificate to KeyStore", e);
                    }
                    count++;
                }
                setTrustManager(ks);
            } finally {
                try {
                    is.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        private static void setTrustManager(KeyStore caKeystore) {
            String defaultTrustAlgorithm = TrustManagerFactory.getDefaultAlgorithm();

            TrustManagerFactory caTrustManagerFactory;
            try {
                caTrustManagerFactory = TrustManagerFactory.getInstance(defaultTrustAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                caTrustManagerFactory = null;
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            try {
                caTrustManagerFactory.init(caKeystore);
            } catch (KeyStoreException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            tm = caTrustManagerFactory.getTrustManagers();
        }

        public static SocketFactory getDefault() {
            synchronized (CustomSocketFactory.class) {
                if (factory == null) {
                    try {
                        factory = new CustomSocketFactory();
                    } catch (KeyManagementException | NoSuchAlgorithmException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }
            }
            return factory;
        }

        public Socket createSocket() throws IOException {
            return sf.createSocket();
        }

        public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
            return sf.createSocket(host, port);
        }

        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
            return sf.createSocket(host, port, localHost, localPort);
        }

        public Socket createSocket(InetAddress host, int port) throws IOException {
            return sf.createSocket(host, port);
        }

        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
            return sf.createSocket(address, port, localAddress, localPort);
        }
    }

    private static class TrustAllX509TrustManager implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            return;
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }


    }
}

