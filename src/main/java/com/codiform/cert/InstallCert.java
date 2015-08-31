package com.codiform.cert;
/**
 * Command-line interface for the InstallCertCommand.
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
