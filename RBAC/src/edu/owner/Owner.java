package edu.owner;

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
 *         This is Owner's main class which is used to encrypt images of
 *         particular location
 */
public class Owner {

	public static Properties property = null;

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
			// String locationPath = (String) property.get("inputLocationPath");

			Registry registry = LocateRegistry.getRegistry(ipAddress, serverPort);
			RemoteSystemAdministrator systemAdministrator = (RemoteSystemAdministrator) registry
					.lookup("systemAdministrator");

			String roleId = args[0];
			String locationPath = args[1];
			OwnerImpl ownerImpl = new OwnerImpl(systemAdministrator);
			ownerImpl.encryptMessage(roleId, locationPath);

		} catch (RemoteException e) {
			e.printStackTrace();
		} catch (NotBoundException e) {
			e.printStackTrace();
		}
	}
}
