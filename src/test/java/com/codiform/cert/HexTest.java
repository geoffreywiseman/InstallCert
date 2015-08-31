package com.codiform.cert;

import static org.junit.Assert.*;

import org.junit.Test;

public class HexTest {

	@Test
	public void testEncodeHexString() {
		assertEquals( "ca fe ba be", Hex.encodeHexString( new byte[] { (byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE } ) );
	}

}
