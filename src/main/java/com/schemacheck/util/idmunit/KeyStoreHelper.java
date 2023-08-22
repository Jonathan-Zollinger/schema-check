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

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class KeyStoreHelper {

    public static void writeCertificatesToKeyStore(String keyStorePath, char[] keyStorePassphrase, String alias, String host, int port) throws Exception {
        X509Certificate[] chain = getCertificates(host, port);

        File file = new File(keyStorePath);

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        if (file.exists()) {
            InputStream in = new FileInputStream(file);
            ks.load(in, keyStorePassphrase);
            in.close();
        } else {
            ks.load(null, null);
        }

        for (int i = 0; i < chain.length; ++i) {
            ks.setCertificateEntry(alias + "-" + i, chain[i]);
        }

        OutputStream out = new FileOutputStream(keyStorePath);
        ks.store(out, keyStorePassphrase);
        out.close();
    }

    //TODO: reconcile with LdapConnector.getCertificates()
    private static X509Certificate[] getCertificates(String host, int port) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore)null);

        X509TrustManager defaultTrustManager = (X509TrustManager)tmf.getTrustManagers()[0];

        SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);

        SSLContext context = SSLContext.getInstance("TLS");

        context.init(null, new TrustManager[]{tm}, null);

        SSLSocketFactory factory = context.getSocketFactory();

        SSLSocket socket = (SSLSocket)factory.createSocket(host, port);

        socket.setSoTimeout(5000);

        try {
            socket.startHandshake();
            socket.close();
            throw new Exception("Certificate is already trusted.");
        } catch (SSLException e) {
            //ignore exception
        } catch (IOException e) {
            //ignore exception
        }

        if (tm.chain == null) {
            throw new Exception("No certificate chain received.");
        }

        return tm.chain;
    }

    public static class SavingTrustManager implements X509TrustManager {
        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        public void checkClientTrusted(X509Certificate[] certChain, String authType) throws CertificateException {
            throw new UnsupportedOperationException();
        }

        public void checkServerTrusted(X509Certificate[] certChain, String authType) throws CertificateException {
            this.chain = certChain;
            tm.checkServerTrusted(certChain, authType);
        }

        public X509Certificate[] getAcceptedIssuers() {
            throw new UnsupportedOperationException();
        }

        public X509Certificate[] getChain() {
            return this.chain;
        }
    }

}
