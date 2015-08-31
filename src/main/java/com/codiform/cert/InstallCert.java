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

/**
 * Class used to add the server's certificate to the KeyStore with your trusted
 * certificates.
 */
public class InstallCert {

	public static void main(String[] args) throws Exception {
		String host;
		int port;

		if ((args.length == 1) || (args.length == 2)) {
			String[] splitHost = args[0].split(":");
			if( splitHost.length > 2 ) {
				printUsage();
				return;
			}
			host = splitHost[0];
			port = (splitHost.length == 1) ? 443 : Integer.parseInt(splitHost[1]);
			String passphrase = (args.length == 1) ? "changeit" : args[1];
			new InstallCertCommand(host, port, passphrase.toCharArray() ).run();
		} else {
			printUsage();
			return;
		}
	}

	private static void printUsage() {
		System.out.println("InstallCert <host[:port]> [passphrase] [alias]");
	}

}
