package org.matthiaszimmermann.crypto.utility;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;

public class FileUtility {

	public static JSONObject readJsonFile(File file) {
		String jsonString = readTextFile(file);

		if(jsonString.isEmpty()) {
			throw new RuntimeException("Empty json file");
		}

		try {
			return new JSONObject(jsonString);
		}
		catch (JSONException e) {
			throw new RuntimeException("Failed to convert json file to json object", e);
		}
	}

	public static String readTextFile(String fileName) {
		try {
			return readTextFile(new File(fileName));
		}
		catch (Exception e) {
			throw new RuntimeException("Failed to read content from text file " + fileName, e);
		}
	}

	public static String readTextFile(File file) {
		
		if(!file.exists()) {
			throw new RuntimeException("File to read does not exist " + file.getAbsolutePath());
		}
		
		if(file.isDirectory()) {
			throw new RuntimeException("Provided path is directory, not file " + file.getAbsolutePath());
		}
		
		StringBuilder sb = new StringBuilder();

		try {
			InputStreamReader isr = new InputStreamReader(new FileInputStream(file), "UTF8");
			BufferedReader in = new BufferedReader(isr);
			String str = null;

			while((str = in.readLine()) != null) {
				sb.append(str);
			}

			in.close();
		}
		catch (Exception e) {
			throw new RuntimeException("Failed to read content from file " + file.getAbsolutePath(), e);
		}

		return sb.toString();
	}

	public static void saveToFile(String buf, String fileName) {
		boolean overwrite = false;
		saveToFile(buf, fileName, overwrite);
	}
	
	public static void saveToFile(byte [] buf, String fileName) {
		boolean overwrite = false;
		saveToFile(buf, fileName, overwrite);
	}
	
	public static void saveToFile(String buf, String fileName, boolean overwrite) {
		verifyFileExists(fileName, overwrite);
		
		try(PrintWriter out = new PrintWriter(fileName)) {
			out.println(buf);
		}
		catch(Exception e) {
			throw new RuntimeException("Failed to write content to file " + fileName, e);
		}
	}

	public static void saveToFile(byte [] buf, String fileName, boolean overwrite) {
		verifyFileExists(fileName, overwrite);
		
		try (FileOutputStream fos = new FileOutputStream(fileName)) {
			fos.write(buf);
		}
		catch(Exception e) {
			throw new RuntimeException("Failed to write content to file " + fileName, e);
		}
	}
	
	private static void verifyFileExists(String fileName, boolean overwrite) {
		if(overwrite) {
			return;
		}
		
		File file = new File(fileName);
		
		if(file.exists()) {
			throw new RuntimeException(String.format("File %s already exits. Not writing anythiong", fileName));
		}
	}

	public static List<String> getResourceAsStrings(String fileName) {
		try {
			InputStream is = FileUtility.class.getResourceAsStream(fileName);
			InputStreamReader isr = new InputStreamReader(is);
			BufferedReader br = new BufferedReader(isr);

			List<String> lines = new ArrayList<>();
			String line = br.readLine();

			while(line != null) {
				lines.add(line);
				line = br.readLine();
			}

			return lines;
		}
		catch (Exception e) {
			throw new RuntimeException("Failed to read text from resource " + fileName, e);
		}
	}

	public static byte [] getResourceAsBytes(String fileName) {
		try {
			InputStream is = FileUtility.class.getResourceAsStream(fileName);
			byte [] buf = getBytesFromInputStream(is);

			return buf;
		}
		catch (Exception e) {
			throw new RuntimeException("Failed to read content from resource " + fileName, e);
		}
	}

	private static byte[] getBytesFromInputStream(InputStream is) throws IOException {
		try (ByteArrayOutputStream os = new ByteArrayOutputStream();) {
			byte[] buffer = new byte[0xFFFF];

			for (int len; (len = is.read(buffer)) != -1;)
				os.write(buffer, 0, len);

			os.flush();

			return os.toByteArray();
		}
	}

}
