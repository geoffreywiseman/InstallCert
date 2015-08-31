package com.codiform.cert;
/**
 * This is my own fork of the InstallCert program originally published by
 * Sun Microsystems here:
 *   http://blogs.sun.com/andreas/resource/InstallCert.java
 * 
 * And then republished and modified here:
 *   https://github.com/escline/InstallCert
 * 
 * The license for that original code follows below.  I wanted to
 * examine the code as I went and make a few modifications, so I forked it,
 * and made some modifications.
 */

/*
 * 
 * Copyright 2006 Sun Microsystems, Inc.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Sun Microsystems nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Class used to add the server's certificate to the KeyStore with your trusted
 * certificates.
 */
public class InstallCertCommand implements Runnable {

	private String host;
	private int port;
	private char[] passphrase;

	public InstallCertCommand(String host, int port, char[] passphrase ) {
		this.host = host;
		this.port = port;
		this.passphrase = passphrase;
	}

	public void run() {
		try {
			KeyStore keystore = getKeystore();
			X509Certificate chain[] = captureCertificateChain(keystore);

			if (chain == null) {
				System.out.println("Could not obtain server certificate chain");
				return;
			}

			printChain(chain);
			Integer index = getIndexToInstall();
			installCertificate(keystore, chain, index);
		} catch (Exception exception) {
			exception.printStackTrace();
		}
	}

	private void installCertificate(KeyStore keystore, X509Certificate[] chain, Integer index) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		X509Certificate cert = chain[ index ];
		String alias = host + "-" + ( index  + 1 );
		keystore.setCertificateEntry(alias, cert);

		OutputStream out = new FileOutputStream("jssecacerts");
		keystore.store(out, passphrase);
		out.close();

		System.out.println();
		System.out.println(cert);
		System.out.println();
		System.out.println("Added certificate to keystore 'jssecacerts' using alias '" + alias + "'");
		System.out.println("You can change this alias with keytool later if you desire." );
	}

	private Integer getIndexToInstall() throws IOException {
		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

		System.out.println("Enter certificate to add to trusted keystore or 'q' to quit: [1]");
		String line = reader.readLine().trim();
		int keyIndex;
		try {
			keyIndex = (line.length() == 0) ? 0 : Integer.parseInt(line) - 1;
		} catch (NumberFormatException e) {
			System.out.println("KeyStore not changed");
			return null;
		}
		return keyIndex;
	}

	private void printChain(X509Certificate[] chain) throws NoSuchAlgorithmException, CertificateEncodingException {
		System.out.println();
		System.out.println("Server sent " + chain.length + " certificate(s):");
		System.out.println();
		MessageDigest sha1 = MessageDigest.getInstance("SHA1");
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		for (int i = 0; i < chain.length; i++) {
			X509Certificate cert = chain[i];
			System.out.println("\t" + (i + 1) + " Subject " + cert.getSubjectDN());
			System.out.println("\t\tIssuer\t" + cert.getIssuerDN());
			sha1.update(cert.getEncoded());
			System.out.println("\t\tsha1\t" + Hex.encodeHexString(sha1.digest()));
			md5.update(cert.getEncoded());
			System.out.println("\t\tmd5\t" + Hex.encodeHexString(md5.digest()));
			System.out.println();
		}
	}

	private X509Certificate[] captureCertificateChain(KeyStore ks) throws NoSuchAlgorithmException, KeyStoreException,
			KeyManagementException, UnknownHostException, IOException {
		SavingTrustManager tm = getSavingTrustManager(ks);
		SSLSocketFactory factory = getSocketFactory(tm);
		connectToServer(factory);
		return tm.chain;
	}

	private void connectToServer(SSLSocketFactory factory) throws IOException, UnknownHostException, SocketException {
		System.out.println("Opening connection to " + host + ":" + port + "...");
		SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
		socket.setSoTimeout(10000);
		try {
			System.out.println("Starting SSL handshake...");
			socket.startHandshake();
			socket.close();
			System.out.println();
			System.out.println("No errors, certificate is already trusted");
		} catch (SSLException e) {
			System.out.println();
			e.printStackTrace(System.out);
		}
	}

	private SSLSocketFactory getSocketFactory(SavingTrustManager tm)
			throws NoSuchAlgorithmException, KeyManagementException {
		SSLContext context = SSLContext.getInstance("TLS");
		context.init(null, new TrustManager[] { tm }, null);
		SSLSocketFactory factory = context.getSocketFactory();
		return factory;
	}

	private SavingTrustManager getSavingTrustManager(KeyStore ks)
			throws NoSuchAlgorithmException, KeyStoreException {
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(ks);
		X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
		SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
		return tm;
	}

	private KeyStore getKeystore() throws FileNotFoundException, KeyStoreException, IOException,
			NoSuchAlgorithmException, CertificateException {
		File keystoreFile = getKeystoreFile();
		System.out.println("Loading KeyStore " + keystoreFile + "...");
		InputStream in = new FileInputStream(keystoreFile);
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(in, passphrase);
		in.close();
		return ks;
	}

	private File getKeystoreFile() {
		File file = new File("jssecacerts");
		if (file.isFile())
			return file;

		String path = System.getProperty("java.home") + File.separatorChar + "lib" + File.separatorChar + "security";
		File dir = new File(path);
		file = new File(dir, "jssecacerts");
		if (file.isFile())
			return file;

		return new File(dir, "cacerts");
	}

}
