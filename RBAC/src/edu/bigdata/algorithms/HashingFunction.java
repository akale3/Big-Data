package edu.bigdata.algorithms;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashingFunction {

	/**
	 * @param input
	 *            String to be hashed by SHA-256
	 * @return Hashed String Value
	 * 
	 *         This Method is used to get the hashed value of any input string
	 *         and returns 256 bit hashed value
	 */
	public String getSHA256HashValue(String input) {

		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance("SHA-256");
			messageDigest.update(input.getBytes());
			byte[] messageBytes = messageDigest.digest();

			StringBuilder stringBuilder = new StringBuilder();
			for (byte b1 : messageBytes) {
				String hexString = Integer.toHexString(b1 & 0xff).toString();
				stringBuilder.append(hexString);
			}
			return stringBuilder.toString();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param input
	 *            String to be hashed by SHA-1
	 * @return Hashed String Value
	 * 
	 *         This Method is used to get the hashed value of any input string
	 *         and returns 160 bit hashed value
	 */
	public String getSHA1HashValue(String input) {

		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance("SHA-1");
			messageDigest.update(input.getBytes());
			byte[] b = messageDigest.digest();

			StringBuilder stringBuilder = new StringBuilder();
			for (byte b1 : b) {
				String hexString = Integer.toHexString(b1 & 0xff).toString();
				stringBuilder.append(hexString);
			}
			return stringBuilder.toString();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
}