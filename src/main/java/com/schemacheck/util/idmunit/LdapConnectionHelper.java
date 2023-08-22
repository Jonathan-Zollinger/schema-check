/*
 * IdMUnit - Automated Testing Framework for Identity Management Solutions
 * Copyright (c) 2005-2016 TriVir, LLC
 *
 * This program is licensed under the terms of the GNU General Public License
 * Version 2 (the "License") as published by the Free Software Foundation, and
 * the TriVir Licensing Policies (the "License Policies").  A copy of the License
 * and the Policies were distributed with this program.
 *
 * The License is available at:
 * http://www.gnu.org/copyleft/gpl.html
 *
 * The Policies are available at:
 * http://www.idmunit.org/licensing/index.html
 *
 * Unless required by applicable law or agreed to in writing, this program is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied.  See the License and the Policies
 * for specific language governing the use of this program.
 *
 * www.TriVir.com
 * TriVir LLC
 * 13890 Braddock Road
 * Suite 310
 * Centreville, Virginia 20121
 *
 */
package com.schemacheck.util.idmunit;


import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.ldap.InitialLdapContext;
import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.*;


/*
 *  @author Kenneth Rawlings
 */
//TODO: remove certificate-related methods to KeyStoreHelper class
//TODO: rename to LdapHelper to allow for general LDAP helper methods?
public class LdapConnectionHelper {
    public static final String CONFIG_USE_TLS = "use-tls";
    public static final String CONFIG_TRUST_ALL_CERTS = "trust-all-certs";
    public static final String CONFIG_TRUSTED_CERT_FILE = "trusted-cert-file";
    public static final String LDAP_CONFIG_PREFIX = "ldap";

    //private static boolean started = false;

    public static InitialLdapContext createLdapConnection(Map<String, String> config) throws IdMUnitException {
        return createLdapConnection("", config);
    }

    public static InitialLdapContext createLdapConnection(String configPrefix, Map<String, String> config)  throws IdMUnitException {
        // normalize configPrefix
        if (configPrefix == null) {
            configPrefix = "";
        }

        String server = config.get(configPrefix + BasicConnector.CONFIG_SERVER);
        String keystorePath = config.get(configPrefix + BasicConnector.CONFIG_KEYSTORE_PATH);
        String trustedCertFile = config.get(configPrefix + CONFIG_TRUSTED_CERT_FILE);

        boolean trustAll = false;
        if (config.get(configPrefix + CONFIG_TRUST_ALL_CERTS) != null) {
            trustAll = Boolean.parseBoolean(config.get(configPrefix + CONFIG_TRUST_ALL_CERTS));
        }

        boolean useTLS = false;
        if (config.get(configPrefix + CONFIG_USE_TLS) != null) {
            useTLS = Boolean.parseBoolean(config.get(configPrefix + CONFIG_USE_TLS));
        } else if (keystorePath != null || trustedCertFile != null || trustAll) {
            useTLS = true;
        }

        String userDN = config.get(configPrefix + BasicConnector.CONFIG_USER);
        String password = config.get(configPrefix + BasicConnector.CONFIG_PASSWORD);

        Map<String, String> envOverride = Collections.emptyMap();
        return createLdapConnection(server, userDN, password, keystorePath, trustedCertFile, useTLS, trustAll, envOverride);
    }

    public static InitialLdapContext createLdapConnection(String server, String userDN, String password, String keystorePath,
                                                          String trustedCertFile, boolean useTLS, boolean trustAll, Map<String,
            String> envOverride) throws IdMUnitException {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("com.sun.jndi.ldap.connect.pool", "true");  //CP CHANGE TO DISABLE LDAP CONNECTION POOL
        env.put("com.sun.jndi.ldap.connect.pool.protocol", "plain ssl");
        env.put("com.sun.jndi.ldap.connect.pool.timeout", "1000");
        env.put("com.sun.jndi.ldap.connect.pool.maxsize", "3");
        env.put("com.sun.jndi.ldap.connect.pool.prefsize", "1");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, userDN);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put("com.sun.jndi.ldap.connect.timeout", "50000");
        env.put(Context.REFERRAL, "follow");
        if (useTLS == false) {
            env.put(Context.PROVIDER_URL, "ldap://" + server);
        } else {
            env.put(Context.PROVIDER_URL, "ldaps://" + server);
            if (keystorePath != null) {
                CustomSocketFactory.setTrustedKeyStore(keystorePath, null);
                env.put("java.naming.ldap.factory.socket", CustomSocketFactory.class.getName());
            } else if (trustedCertFile != null) {
                CustomSocketFactory.setTrustedCert(trustedCertFile);
                env.put("java.naming.ldap.factory.socket", CustomSocketFactory.class.getName());
            } else if (trustAll) {
                CustomSocketFactory.setTrustAll();
                env.put("java.naming.ldap.factory.socket", CustomSocketFactory.class.getName());
            }
        }

        //TODO: Loop is does nothing as is: Update to loop over the 'envOverride' map.
        for (Map.Entry<String, String> entry : env.entrySet()) {
            String envKey = entry.getKey();
            if (env.containsKey(envKey)) {
//ignore
            } else {
//ignore
            }

            env.put(entry.getKey(), entry.getValue());
        }

        try {
            return new InitialLdapContext(env, null);
        } catch (NamingException e) {
            if (useTLS) {
                if (keystorePath != null) {
                    
                } else if (trustedCertFile != null) {
                    
                } else if (trustAll) {
                    
                } else {
                    if (System.getProperty("javax.net.ssl.trustStore") != null) {
                        
                    } else {
                        final char sep = File.separatorChar;
                        final String jssecacerts = System.getProperty("java.home") + sep + "lib" + sep + "security" + sep + "jssecacerts";
                        String defaultKeystore;
                        if (new File(jssecacerts).exists()) {
                            defaultKeystore = jssecacerts;
                        } else {
                            defaultKeystore = System.getProperty("java.home") + sep + "lib" + sep + "security" + sep + "cacerts";
                        }
                        
                    }
                }

                exportCertificate(server, trustedCertFile);
                throw new IdMUnitException("Failed to obtain an SSL LDAP Connection: " + e.getMessage(), e);
            } else {
                
                throw new IdMUnitException("Failed to obtain an LDAP Connection: " + e.getMessage(), e);
            }
        }
    }

    private static void exportCertificate(String server, String trustedCertFile) throws IdMUnitException {
        String host;
        int port = 636;
        if (server.indexOf(':') == -1) {
            host = server;
        } else {
            int j = server.indexOf(':');
            host = server.substring(0, j);
            port = Integer.parseInt(server.substring(j + 1));
        }

        String certFilePath;
        if (trustedCertFile != null) {
            certFilePath = trustedCertFile;
        } else {
            if (port == 636) {
                certFilePath = host + ".cer";
            } else {
                certFilePath = host + "_" + port + ".cer";
            }
        }

        writeCertificatesToFile(certFilePath, host, port);
        
    }

    private static void writeCertificatesToFile(String certFilePath, String host, int port) throws IdMUnitException {
        X509Certificate[] chain = getCertificates(host, port);

        FileOutputStream os;
        try {
            os = new FileOutputStream(certFilePath);
        } catch (FileNotFoundException e) {
            throw new IdMUnitException("Error opening to file '" + certFilePath + "'");
        }

        try {
            for (int i = 0; i < chain.length; i++) {
                byte[] buf;
                try {
                    buf = chain[i].getEncoded();
                } catch (CertificateEncodingException e) {
                    throw new IdMUnitException("Error encoding certificate.", e);
                }

                Writer wr = new OutputStreamWriter(os, Charset.forName("UTF-8"));
                try {
                    wr.write("-----BEGIN CERTIFICATE-----\n");
                    wr.write(Base64.getEncoder().encodeToString(buf) + "\n");
                    wr.write("-----END CERTIFICATE-----\n");
                    wr.flush();
                } catch (IOException e) {
                    throw new IdMUnitException("Error writing certificate to file '" + certFilePath + "'");
                }
            }
        } finally {
            try {
                os.close();
            } catch (IOException e) {
                //ignore exception
            }
        }
    }

    //TODO: reconcile with KeyStoreHelper.getCertificates()
    private static X509Certificate[] getCertificates(String host, int port) throws IdMUnitException {
        TrustManagerFactory tmf;
        try {
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new IdMUnitException("Error getting TrustManagerFactory.", e);
        }

        try {
            tmf.init((KeyStore)null);
        } catch (KeyStoreException e) {
            throw new IdMUnitException("Error initializing TrustManagerFactory.", e);
        }

        X509TrustManager defaultTrustManager = (X509TrustManager)tmf.getTrustManagers()[0];

        KeyStoreHelper.SavingTrustManager tm = new KeyStoreHelper.SavingTrustManager(defaultTrustManager);

        SSLContext context;
        try {
            context = SSLContext.getInstance("TLS");
        } catch (NoSuchAlgorithmException e) {
            throw new IdMUnitException("Error getting SSLContext.", e);
        }

        try {
            context.init(null, new TrustManager[] {tm}, null);
        } catch (KeyManagementException e) {
            throw new IdMUnitException("Error initializing SSLContext.", e);
        }

        SSLSocketFactory factory = context.getSocketFactory();

        SSLSocket socket;
        try {
            socket = (SSLSocket)factory.createSocket(host, port);
        } catch (UnknownHostException e) {
            throw new IdMUnitException("Error creating socket.", e);
        } catch (IOException e) {
            throw new IdMUnitException("Error creating socket.", e);
        }

        try {
            socket.setSoTimeout(50000);
        } catch (SocketException e) {
            throw new IdMUnitException("Error setting socket timeout.", e);
        }

        try {
            socket.startHandshake();
            socket.close();
        } catch (SSLException e) {
            //ignore exception
        } catch (IOException e) {
            //ignore exception
        }

        if (tm.getChain() == null) {
            throw new IdMUnitException("No certificate chain received.");
        }

        return tm.getChain();
    }

    public static void destroyLdapConnection(DirContext context) throws IdMUnitException {
        try {
            if (context != null) {
                context.close();
                context = null;
            }
        } catch (NamingException e) {
            throw new IdMUnitException("Failed to close ldap connection: " + e.getMessage());
        }
    }

    public static Attributes getAttributes(DirContext context, String dn) throws IdMUnitException {
        try {
            DirContext tmp = (DirContext)context.lookup(dn);
            close(tmp); //this is necessary in order to keep the parent connection ctx clean enough to be pooled/managed as week references inside of the parent DirContext will prevent proper pooling
        } catch (NameNotFoundException e) {
            throw new IdMUnitException("Could not find object: [" + dn + "] to retrieve attributes.", e);
        } catch (NamingException e) {
            throw new IdMUnitException("Error resolving '" + dn + "'.", e);
        }

        try {
            return context.getAttributes(dn);
        } catch (NamingException e) {
            throw new IdMUnitException("Error reading attributes for '" + dn + "'.", e);
        }
    }

    public static Map<String, Collection<String>> attributesToMap(Attributes attributes) throws IdMUnitException {
        TreeMap<String, Collection<String>> attrs = new TreeMap<String, Collection<String>>(String.CASE_INSENSITIVE_ORDER);

        if (attributes == null) {
            return attrs;
        }

        NamingEnumeration<? extends Attribute> i = null;
        try {
            for (i = attributes.getAll(); i.hasMore(); ) {
                Attribute attr = i.next();
                String attrName = attr.getID();
                List<String> attrValues = new LinkedList<String>();
                for (NamingEnumeration<?> j = attr.getAll(); j.hasMore(); ) {
                    Object value = j.next();
                    if (value instanceof byte[]) {
                        attrValues.add(Base64.getEncoder().encodeToString((byte[])value));
                    } else if (value instanceof String) {
                        attrValues.add((String)value);
                    } else {
                        
                    }
                }
                attrs.put(attrName, attrValues);
            }
        } catch (NamingException e) {
            close(i);
            throw new IdMUnitException("Error converting attributes", e);
        }

        return attrs;
    }

    public static void close(DirContext context) {
        if (context != null) {
            try {
                context.close();
            } catch (NamingException e) {
                
            }
        }
    }

    public static void close(NamingEnumeration naming) {
        if (naming != null) {
            try {
                naming.close();
            } catch (NamingException e) {
                //ignore
            }
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
                    } catch (KeyManagementException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    } catch (NoSuchAlgorithmException e) {
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
