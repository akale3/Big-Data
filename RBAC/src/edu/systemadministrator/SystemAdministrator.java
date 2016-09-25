package edu.systemadministrator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.ArrayList;
import java.util.Map.Entry;
import java.util.Properties;

public class SystemAdministrator {

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

			// Registering remote system administrator for communication over
			// the network
			RemoteSystemAdministrator systemAdministrator = RemoteSystemAdministratorImpl
					.getRemoteSystemAdministratorImplInstance();

			int serverPort = Integer.parseInt(property.getProperty("portNumber").toString());
			Registry registry = LocateRegistry.createRegistry(serverPort);

			registry.bind("systemAdministrator", systemAdministrator);
			System.out.println("System Administrator Started :");

			System.out.println("Initializing Setup...");
			RemoteSystemAdministratorImpl administratorImpl = RemoteSystemAdministratorImpl
					.getRemoteSystemAdministratorImplInstance();
			administratorImpl.initialize();

			// Initialize Roles
			System.out.println("Initializing Roles...");
			RoleManager roleManager = RoleManager.getRoleManagerInstance();
			roleManager.initialize();
			roleManager.initializeRole();

			// Manage Roles
			System.out.println("Creating Role User Relationship...");
			for (Entry<String, ArrayList<String>> entry : roleManager.getRoleMap().entrySet()) {
				if (null != entry.getValue()) {
					systemAdministrator.manageRole(entry.getKey(), entry.getValue());
				} else {
					systemAdministrator.manageRole(entry.getKey(), null);
				}
			}

			System.out.println("Adding User to Role User List...");
			roleManager.addUser("aditya.kale_1990", "RoleId1_12345678");
			roleManager.addUser("aditya.kale_1992", "RoleId2_12345678");
			roleManager.addUser("aditya.kale_1993", "RoleId3_12345678");
			roleManager.addUser("aditya.kale_1994", "RoleId4_12345678");

			System.out.println("All Users are added successfully.\nSetup is ready...");
			System.out.println("Ready to accept Requests....");

		} catch (RemoteException e) {
			e.printStackTrace();
		} catch (AlreadyBoundException e) {
			e.printStackTrace();
		}
	}
}
