package edu.systemadministrator;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

public interface RemoteSystemAdministrator extends Remote {

	public Element getS() throws RemoteException;

	public Element getG() throws RemoteException;

	public HashMap<String, byte[]> getDecriptionKeyParams(String roleId, String userId, String location)
			throws RemoteException;

	public void manageRole(String roleId, ArrayList<String> ancestorIds) throws RemoteException;

	public Field getZr() throws RemoteException;

	public Element getV() throws RemoteException;

	public Element getW() throws RemoteException;

	public Element getRoleSecretKey(String roleId) throws RemoteException;

	public Element getK() throws RemoteException;

	public HashMap<String, ArrayList<String>> getRoleUserMap() throws RemoteException;

	public HashMap<String, byte[]> getRoleUserParametersInBytes(String roleId) throws RemoteException;

	public HashMap<String, HashMap<String, Element>> getRoleUserParameters() throws RemoteException;

	public byte[] getDecryptionKey(String userId) throws RemoteException;

	public HashMap<String, byte[]> getRolePublicParameters(String roleId) throws RemoteException;

	public HashMap<String, byte[]> getPublicKey() throws RemoteException;

	public HashMap<String, byte[]> getMasterKey() throws RemoteException;

	public void setRoleCipherText(String roleId, HashMap<String, byte[]> cipherParts, String locationPath)
			throws RemoteException;

	public void addPairToKeyMap(String roleId, String location, String encKey) throws RemoteException;

	public HashMap<String, ArrayList<String>> getKeyMap() throws RemoteException;

	public HashMap<String, byte[]> getLocationCipher(String location) throws RemoteException;
	
	public LinkedHashMap<String, ArrayList<String>> getRoleMap()throws RemoteException;
}
