package edu.user;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Properties;

import edu.systemadministrator.RemoteSystemAdministrator;

/**
 * @author aditya, ashish
 * 
 *         This is User's main class which is used to dencrypt images of
 *         particular location
 */
public class User {

	public static Properties property = null;
	private static String USER_ID = "aditya.kale_1990";

	public static void main(String[] args) {

		property = new Properties();
		try {
			property.load(new FileInputStream(new File("./resources/config.properties")));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		try {
			int serverPort = Integer.parseInt(property.getProperty("portNumber").toString());
			String ipAddress = property.getProperty("ipAddress");

			Registry registry = LocateRegistry.getRegistry(ipAddress, serverPort);
			RemoteSystemAdministrator systemAdministrator = (RemoteSystemAdministrator) registry
					.lookup("systemAdministrator");

			// String locationPath = (String) property.get("inputLocationPath");
			UserImpl userImpl = new UserImpl(USER_ID, systemAdministrator);
			String roleId = args[0];
			String locationPath = args[1];
			userImpl.decryptMessage(USER_ID, roleId, locationPath);

		} catch (RemoteException e) {
			e.printStackTrace();
		} catch (NotBoundException e) {
			e.printStackTrace();
		}
	}
}
