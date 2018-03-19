package org.matthiaszimmermann.crypto.utility;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import javax.crypto.SecretKey;

import org.junit.Test;
import org.matthiaszimmermann.crypto.common.BaseTest;
import org.matthiaszimmermann.crypto.utility.AesUtility;

public class AesUtilityTest extends BaseTest {
	
	public static final String PASS_PHRASE = "pass phrase";
	public static final String TEXT_PLAIN = "the quick brown fox jumps over the lazy dog";
	public static final String TEXT_BASE64_ENCODED = "YbbyQ563fQvzNu2zVd3zvDvJh41zxSshL/D2iFFvWJBHhYxNcIcuFZGBaL1cJAip";
	public static final String AES_IV = "mW1YouWJhVb2QMtOMLBsog==";
	
	private static final byte [] SALT = new String("ldsqDQvEWJyWZMCl").getBytes();
	private static final int ITERATION_COUNT = 65536;
	private static final int KEY_STRENGTH = 256;

	private static final String PASS_PHRASE_DIFFERENT = "different pass phrase";
	private static final byte [] SALT_DIFFERENT = new String("2iFFvWJBHhYxNcIcuFZGBaL1").getBytes();
	private static final int ITERATION_COUNT_DIFFERENT = 32768;
	private static final int KEY_STRENGTH_DIFFERENT = 128;

	@Test
	public void testBase64encoding() throws IOException {
		log("--- start testBase64encoding() ---");
		
		byte [] bytes = AesUtility.base64ToBytes(TEXT_BASE64_ENCODED);
		assertNotNull(bytes);
		assertTrue(bytes.length > 0);
		
		log("input string: '%s'", TEXT_BASE64_ENCODED);
		log("bytes.length=%d, bytes[0]=%d", bytes.length, bytes[0]);
		
		String string = AesUtility.bytesToBase64(bytes);
		assertNotNull(string);
		assertTrue(string.length() > 0);

		log("output.length()=%d, output: '%s'", string.length(), string);
		assertEquals(TEXT_BASE64_ENCODED, string);

		log("--- end testBase64encoding() ---");
	}
	
	@Test
	public void testUtilityConstructor() throws Exception {
		log("--- start testUtilityConstructor() ---");
		
		// verify default key generation
		AesUtility aesDefault = new AesUtility(PASS_PHRASE);
		AesUtility aesDefaultValues = new AesUtility(PASS_PHRASE, SALT, ITERATION_COUNT, KEY_STRENGTH);
		
		SecretKey keyDefault = aesDefault.getSecretKey();
		SecretKey keyDefaultValues = aesDefaultValues.getSecretKey();
		
		byte [] bytesDefault = keyDefault.getEncoded();
		byte [] bytesDefaultValues = keyDefaultValues.getEncoded();
		
		assertArrayEquals(bytesDefault, bytesDefaultValues);
		
		// verify that different constructor values lead to different keys
		AesUtility aes1 = new AesUtility(PASS_PHRASE_DIFFERENT, SALT, ITERATION_COUNT, KEY_STRENGTH);
		AesUtility aes2 = new AesUtility(PASS_PHRASE, SALT_DIFFERENT, ITERATION_COUNT, KEY_STRENGTH);
		AesUtility aes3 = new AesUtility(PASS_PHRASE, SALT, ITERATION_COUNT_DIFFERENT, KEY_STRENGTH);
		AesUtility aes4 = new AesUtility(PASS_PHRASE, SALT, ITERATION_COUNT, KEY_STRENGTH_DIFFERENT);
		
		String encodedDefault = AesUtility.bytesToBase64(bytesDefault);
		String encoded1 = getEncodedKey(aes1);
		String encoded2 = getEncodedKey(aes2);
		String encoded3 = getEncodedKey(aes3);
		String encoded4 = getEncodedKey(aes4);
		
		log("encoded key default: '%s'", encodedDefault);
		log("key 1 default: '%s'", encoded1);
		log("key 2 default: '%s'", encoded2);
		log("key 3 default: '%s'", encoded3);
		log("key 4 default: '%s'", encoded4);
		
		// check that all keys are different
		assertNotEquals(encodedDefault, encoded1);
		assertNotEquals(encodedDefault, encoded2);
		assertNotEquals(encodedDefault, encoded3);
		assertNotEquals(encodedDefault, encoded4);

		assertNotEquals(encoded1, encoded2);
		assertNotEquals(encoded1, encoded3);
		assertNotEquals(encoded1, encoded4);
		assertNotEquals(encoded2, encoded3);
		assertNotEquals(encoded2, encoded4);
		assertNotEquals(encoded3, encoded4);
		
		// check key length are the same except for key 4 (lower key strength)
		assertEquals(encodedDefault.length(), encoded1.length());
		assertEquals(encodedDefault.length(), encoded2.length());
		assertEquals(encodedDefault.length(), encoded3.length());
		assertTrue(encodedDefault.length() > encoded4.length());

		log("--- end testUtilityConstructor() ---");
	}
	
	@Test
	public void testSecretKeyGeneration() throws Exception {
		AesUtility aes1 = new AesUtility(PASS_PHRASE, SALT, ITERATION_COUNT, 64);
		AesUtility aes2 = new AesUtility(PASS_PHRASE, SALT, ITERATION_COUNT, 128);
		AesUtility aes3 = new AesUtility(PASS_PHRASE, SALT, ITERATION_COUNT, 256);
		AesUtility aes4 = new AesUtility(PASS_PHRASE, SALT, ITERATION_COUNT, 512);
		
		assertEquals(64/8, aes1.getSecretKey().getEncoded().length);
		assertEquals(128/8, aes2.getSecretKey().getEncoded().length);
		assertEquals(256/8, aes3.getSecretKey().getEncoded().length);
		assertEquals(512/8, aes4.getSecretKey().getEncoded().length);
	}
	
	private String getEncodedKey(AesUtility utility) {
		return AesUtility.bytesToBase64(utility.getSecretKey().getEncoded());
	}
	
	@Test
	public void testEncrypting() throws Exception {
		log("--- start testEncrypting() ---");
		
		AesUtility aes = new AesUtility(PASS_PHRASE);
		String textEncrypted = aes.encrypt(TEXT_PLAIN);
		String iv = aes.getIv();
		
		log("input text: '%s'", TEXT_PLAIN);
		log("pass phrase: '%s'", PASS_PHRASE);
		log("encrypted text: '%s'" , textEncrypted);
		log("iv: '%s'", iv);
		
		assertFalse(textEncrypted.isEmpty());
		assertNotEquals(TEXT_PLAIN, textEncrypted);
		
		String textDecrypted = aes.decrypt(textEncrypted, iv);

		log("decrpyted text: '%s'" , textDecrypted);
		
		assertFalse(textDecrypted.isEmpty());
		assertEquals(TEXT_PLAIN, textDecrypted);
		
		log("--- end testEncrypting() ---");
	}

	@Test
	public void testSeedEncryptionDecryption() throws Exception {
		String passPhrase = "wallet pass phrase";
		String seed = "UWCSITHWQIFMVPAGZHKMJVJG9DKQTDNJQLB9DUJNFCT9AZPZSVQNHDHHXQUFCOOFSLOMMLXZLYNSH9MLJ";
		String seedEncrypted = "dH8FpypngYR+6TkQN9tHudcqz8F/ozo5WaxKM923BZAnSJufzSwHnvgCYHeKF6alwpne0kLuoh9lV0VU0zjkaO/uOHqL5nLmH/q8xSEpi8RRpwftRTxIUTnaWtdFDW9D";
		String iv = "sJpV7caBKM1AXvzWGmZCDg==";
		
		AesUtility aes = new AesUtility(passPhrase);
		String seedDec = aes.decrypt(seedEncrypted, iv);
		assertEquals(seed, seedDec);
	}
	
	@Test
	public void testDecrypting() throws Exception {
		log("--- start testDecrypting() ---");
		
		AesUtility aes = new AesUtility(PASS_PHRASE);
		String textDecrypted = aes.decrypt(TEXT_BASE64_ENCODED, AES_IV);
		
		log("input data: '%s'" , TEXT_BASE64_ENCODED);
		log("pass phrase: '%s'", PASS_PHRASE);
		log("iv: '%s'", AES_IV);
		log("decrypted text: '%s'", textDecrypted);
		
		assertFalse(textDecrypted.isEmpty());
		assertEquals(TEXT_PLAIN, textDecrypted);
		
		String textEncrypted = aes.encrypt(textDecrypted);
		
		assertFalse(textEncrypted.isEmpty());
		assertNotEquals(TEXT_PLAIN, textEncrypted);

		log("encrypted text: '%s'" , textEncrypted);
		log("--- end testDecrypting() ---");
	}
	
	@Test
	public void testRepeatedEncryption() throws Exception {
		log("--- start testRepeatedEncodings() ---");
		
		AesUtility aes = new AesUtility(PASS_PHRASE);
		
		String textEncoded1 = aes.encrypt(TEXT_PLAIN); String iv1 = aes.getIv();
		String textEncoded2 = aes.encrypt(TEXT_PLAIN); String iv2 = aes.getIv();
		String textEncoded3 = aes.encrypt(TEXT_PLAIN); String iv3 = aes.getIv();
		
		log("encrypted[1]='%s', iv[1]='%s'", textEncoded1, iv1);
		log("encrypted[2]='%s', iv[2]='%s'", textEncoded2, iv2);
		log("encrypted[3]='%s', iv[3]='%s'", textEncoded3, iv3);
		
		assertNotEquals(textEncoded1, textEncoded2);
		assertNotEquals(textEncoded1, textEncoded3);
		assertNotEquals(textEncoded2, textEncoded3);
		
		assertNotEquals(iv1, iv2);
		assertNotEquals(iv1, iv3);
		assertNotEquals(iv2, iv3);
		
		log("--- end testRepeatedEncodings() ---");
	}
}
