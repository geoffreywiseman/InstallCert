package com.codiform.cert;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * A simple decorator for the trust manager in order to hang on to the certificate chain, 
 * where it can be retrieved.
 * 
 * The first version of this code was part of {@link InstallCert}, I've extracted it.
 * 
 * This has been changed since the original InstallCert due to some changes in Java 7, along these lines:
 * http://infposs.blogspot.kr/2013/06/installcert-and-java-7.html
 */
class SavingTrustManager implements X509TrustManager {

	private final X509TrustManager tm;
	X509Certificate[] chain;

	SavingTrustManager(X509TrustManager tm) {
		this.tm = tm;
	}

	public X509Certificate[] getAcceptedIssuers() {
		return new X509Certificate[0];
	}

	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		throw new UnsupportedOperationException();
	}

	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		this.chain = chain;
		tm.checkServerTrusted(chain, authType);
	}
}