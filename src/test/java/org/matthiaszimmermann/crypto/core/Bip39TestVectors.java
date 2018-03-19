package org.matthiaszimmermann.crypto.core;

import java.io.File;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.matthiaszimmermann.crypto.utility.FileUtility;

/**
 * Reads and provides BIP39 test vectors. 
 * Test sample copied from Reference implementation of BIP-0039.
 * See {@link https://github.com/trezor/python-mnemonic/blob/master/vectors.json}
 */
public class Bip39TestVectors {
	
	public static final String TEST_VECTORS_FILE = "mnemonic/vectors.json";
	public static final int IDX_ENTROPY = 0;
	public static final int IDX_MNEMONIC = 1;
	public static final int IDX_SEED = 2;

	private File file = null;
	private JSONObject parent = null;
	private JSONArray english = null;
	
	/**
	 * Constructor loading the test samples.
	 */
	public Bip39TestVectors() throws JSONException {
		loadVectors();
	}
	
	private void loadVectors() throws JSONException {
		ClassLoader classLoader = getClass().getClassLoader();
		file = new File(classLoader.getResource(TEST_VECTORS_FILE).getFile());
		String text = FileUtility.readTextFile(file);
		parent = new JSONObject(text);
		english = parent.getJSONArray("english");
	}
	
	public File getFile() {
		return file;
	}
	
	public int length() {
		return english.length();
	}
	
	public byte [] getEntropy(int index) throws JSONException {
		String hex = english.getJSONArray(index).getString(IDX_ENTROPY);
		return hexToBytes(hex);
	}
	
	public String getMnemonic(int index) throws JSONException {
		return english.getJSONArray(index).getString(IDX_MNEMONIC);
	}
	
	public String getSeed(int index) throws JSONException {
		return english.getJSONArray(index).getString(IDX_SEED);
	}
	
	/**
	 * https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
	 */
	private static byte[] hexToBytes(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
}
