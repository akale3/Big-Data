package edu.filecreation;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Random;

/**
 * This is a utility class which is used to create files of different file size.
 * 
 * @author aditya, ashish
 *
 */
public class creatingFiles {

	private final static String FOLDER_LOCATION = "./inputFolder/";
	private final static String FILE_PREFIX = "file_";
	private static Random generator = new Random();

	/**
	 * @param fileCount
	 * @param fileSizeMin
	 * @param fileSizeMax
	 * 
	 * @return This method takes input parameters and generates based on given
	 *         size and count of the files.
	 * 
	 */
	private static void generateFiles(int fileCount, int fileSizeMin, int fileSizeMax) {
		FileOutputStream outputStream;
		byte[] randomData;
		int fileSizeInBytes;

		try {
			for (int i = 0; i < fileCount; i++) {
				outputStream = new FileOutputStream(FOLDER_LOCATION + FILE_PREFIX + i + ".txt");
				fileSizeInBytes = fileSizeMax;
				randomData = getByteArrayOfSize(fileSizeInBytes);
				outputStream.write(randomData);
				outputStream.close();
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * @param numberOfBytes
	 * @return generates bytes array of specified byte size
	 */
	public static byte[] getByteArrayOfSize(int numberOfBytes) {
		byte[] randomData = new byte[numberOfBytes];
		generator.nextBytes(randomData);
		return randomData;
	}

	public static void main(String[] args) {
		int maxfiles = Integer.parseInt(args[0]);
		int fileSize = Integer.parseInt(args[1]);
		generateFiles(maxfiles, 1, fileSize);
	}
}
