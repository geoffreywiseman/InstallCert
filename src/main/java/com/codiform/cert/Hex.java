package com.codiform.cert;

/**
 * This class is simply a method extracted from InstallCert, with one slight modification -- it drops the last space (which isn't needed as a separator).
 */
public class Hex {

	private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

	public static String encodeHexString(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 3);
		for (int b : bytes) {
			b &= 0xff;
			sb.append(HEXDIGITS[b >> 4]);
			sb.append(HEXDIGITS[b & 15]);
			sb.append(' ');
		}
		sb.deleteCharAt(sb.length()-1);
		return sb.toString();
	}

}
