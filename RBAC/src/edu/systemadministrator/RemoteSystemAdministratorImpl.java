package edu.systemadministrator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map.Entry;
import java.util.Properties;

import edu.bigdata.algorithms.HashingFunction;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class RemoteSystemAdministratorImpl extends UnicastRemoteObject implements RemoteSystemAdministrator {

	private Field Zr = null;
	private Field G1 = null;
	private Field G2 = null;
	private Field GT = null;
	private Pairing pairing = null;
	private Element g = null;
	private Element s = null;
	private Element h = null;
	private Element k = null;
	private Element v = null;
	private Element w = null;
	private HashMap<String, HashMap<String, Element>> rolePublicParameters;
	private HashMap<String, HashMap<String, Element>> roleUserParameters;
	private HashMap<String, ArrayList<String>> roleUserMap;
	private HashMap<String, ArrayList<String>> keyMap;
	private HashMap<String, HashMap<String, Element>> roleCipherText;
	private HashMap<String, HashMap<String, byte[]>> messageCipherMap;
	private HashingFunction hashingFunction = null;
	private RoleManager roleManager = null;
	public LinkedHashMap<String, ArrayList<String>> roleMap = null;
	private static RemoteSystemAdministratorImpl remoteSystemAdministratorImpl = null;

	Properties property = null;
	private HashMap<String, Element> mk = null;
	private HashMap<String, Element> pk = null;

	private RemoteSystemAdministratorImpl() throws RemoteException {

	}

	/**
	 * This method initialize all parameters required for RBE setup. Also it
	 * initialize all maps where all data is stored in our application.
	 */
	public void initialize() {
		this.pairing = PairingFactory.getPairing("./resources/a.properties");
		this.Zr = pairing.getZr();
		this.G1 = pairing.getG1();
		this.G2 = pairing.getG2();
		this.GT = pairing.getGT();
		this.g = this.G1.newRandomElement();
		this.h = this.G2.newRandomElement();
		this.s = this.Zr.newRandomElement();
		this.k = this.Zr.newRandomElement();
		rolePublicParameters = new HashMap<String, HashMap<String, Element>>();
		roleUserMap = new HashMap<String, ArrayList<String>>();
		roleUserParameters = new HashMap<String, HashMap<String, Element>>();
		roleCipherText = new HashMap<String, HashMap<String, Element>>();
		hashingFunction = new HashingFunction();
		keyMap = new HashMap<String, ArrayList<String>>();
		messageCipherMap = new HashMap<String, HashMap<String, byte[]>>();
		property = new Properties();
		try {
			property.load(new FileInputStream(new File("./resources/config.properties")));
			System.out.println("Printing g BigInteger value" + g.toBigInteger());
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		roleManager = RoleManager.getRoleManagerInstance();
		intialiseSetup();
	}

	/**
	 * It setups and generates all parameters and publick keys required in RBE
	 * scheme
	 */
	public void intialiseSetup() {

		this.w = getH().powZn(s);

		this.v = this.pairing.pairing(getG(), getH());

		this.mk = new HashMap<String, Element>();
		mk.put("s", getS());
		mk.put("k", getK());
		mk.put("h", getH());

		int q = Integer.parseInt(property.get("max.numberOf.users.per.role").toString());

		this.pk = new HashMap<String, Element>();
		pk.put("w", getW());
		pk.put("v", getV());
		pk.put("gk", getG().powZn(getK()));
		pk.put("g", getG());
		for (int i = 1; i <= q; i++) {
			pk.put("gs" + i, getG().powZn(getS().pow(BigInteger.valueOf(i))));
		}

	}

	/*
	 * This Method generates Public Parameters for a particular Role
	 */
	public void manageRole(String roleId, ArrayList<String> ancestorIds) {
		HashMap<String, Element> pubParameters = new HashMap<String, Element>();

		Element aR = computeAr(roleId, ancestorIds);
		pubParameters.put("Ar", aR);
		Element arDuplicate = aR.duplicate();

		Element bR = arDuplicate.powZn(getK());
		pubParameters.put("Br", bR);

		rolePublicParameters.put(roleId, pubParameters);
		roleUserMap.put(roleId, new ArrayList<String>());
	}

	private Element computeAr(String roleId, ArrayList<String> ancestorIds) {
		String hasedRoleId = this.hashingFunction.getSHA1HashValue(roleId);
		BigInteger hasedRoleIdVal = getBigIntegerValOfString(hasedRoleId);
		Element temp = getZr().newElement();
		temp.set(hasedRoleIdVal);

		Element firstTerm = getS().add(temp);

		Element multiplicatedValue = getZr().newOneElement();
		if (null != ancestorIds && !ancestorIds.isEmpty()) {
			for (String ancestorId : ancestorIds) {
				String hasedAncestorId = this.hashingFunction.getSHA1HashValue(ancestorId);
				BigInteger ancestorIdVal = getBigIntegerValOfString(hasedAncestorId);
				Element temp1 = getZr().newElement();
				temp1.set(ancestorIdVal);
				Element addition = getS().add(temp1);
				multiplicatedValue = multiplicatedValue.mulZn(addition);
			}
		}

		Element multiplyTwoTerms = firstTerm.mulZn(multiplicatedValue);

		Element Ar = getH().powZn(multiplyTwoTerms);
		return Ar;
	}

	/*
	 * This Method returns a byte array of an user's private key DKu.
	 */
	public byte[] getDecryptionKey(String userId) {
		String hashedValue = hashingFunction.getSHA1HashValue(userId);
		BigInteger hashedUserId = getBigIntegerValOfString(hashedValue);
		Element temp = getZr().newElement();
		temp.set(hashedUserId);

		Element additionOfElements = getS().add(temp);
		Element InvertOfAddition = additionOfElements.invert();

		Element userDecryptionKey = getH().powZn(InvertOfAddition);
		return userDecryptionKey.toBytes();
	}

	/*
	 * This Method returns a Role's secret key Skr.
	 */
	public Element getRoleSecretKey(String roleId) {
		String hashedValue = this.hashingFunction.getSHA1HashValue(roleId.toString());
		BigInteger hashedRoleId = getBigIntegerValOfString(hashedValue);

		Element temp = getZr().newElement();
		temp.set(hashedRoleId);

		Element additionWithS = getS().add(temp);
		Element InvertOfAddition = additionWithS.invert();

		Element roleSecretKey = getG().powZn(InvertOfAddition);
		return roleSecretKey;
	}

	/*
	 * This method returns the decryption key parameters based on role id and
	 * user id.
	 */
	@Override
	public HashMap<String, byte[]> getDecriptionKeyParams(String roleId, String userId, String location) {
		HashMap<String, byte[]> decriptionKeyParamMap = new HashMap<String, byte[]>();

		// Compute D
		Element D = computeDValue(roleId, location);
		decriptionKeyParamMap.put("D", D.toBytes());

		// Compute Aux1
		Element Aux1 = computeAux1Value(roleId);
		decriptionKeyParamMap.put("Aux1", Aux1.toBytes());
		// System.out.println("Aux1 = " + Aux1);

		// Compute Aux2
		Element Aux2 = computeAux2Value(roleId, userId);
		decriptionKeyParamMap.put("Aux2", Aux2.toBytes());
		// System.out.println("Aux2 = " + Aux2);

		// Compute g^Pi.M(s)
		Element gPiMs = computegPiMsValue(roleId);
		decriptionKeyParamMap.put("gPiMs", gPiMs.toBytes());
		// System.out.println("gPiMs= " + gPiMs);

		// Compute g^Pk.N(s)
		Element gPkNs = computegPkNsValue(roleId, userId);
		decriptionKeyParamMap.put("gPkNs", gPkNs.toBytes());
		// System.out.println("gPkNs= " + gPkNs);

		return decriptionKeyParamMap;
	}

	private Element computegPkNsValue(String roleId, String userId) {
		ArrayList<String> roleUserList = this.roleUserMap.get(roleId);
		Element multiplicatedValue1 = getZr().newOneElement();
		Element multiplicatedValue2 = getZr().newOneElement();

		if (null != roleUserList && roleUserList.size() > 0) {
			for (String userRoleId : roleUserList) {
				if (!userId.equalsIgnoreCase(userRoleId)) {
					String hasheduserId = this.hashingFunction.getSHA1HashValue(userRoleId);
					BigInteger hashedUserRoleIdVal = getBigIntegerValOfString(hasheduserId);
					Element temp = getZr().newElement();
					temp.set(hashedUserRoleIdVal);
					multiplicatedValue2 = multiplicatedValue2.mulZn(temp);
					multiplicatedValue1 = multiplicatedValue1.mulZn(getS().add(temp));
				}
			}
		}

		Element termSubstraction = multiplicatedValue1.sub(multiplicatedValue2);
		Element sInverse = getS().invert();

		Element PkNs = sInverse.mulZn(termSubstraction);

		Element g = getG();
		Element gPkNs = g.powZn(PkNs);
		return gPkNs;
	}

	private Element computegPiMsValue(String roleId) {
		ArrayList<String> ancestorRoles = this.roleManager.getRoleMap().get(roleId);
		Element multiplicatedValue1 = getZr().newOneElement();
		Element multiplicatedValue2 = getZr().newOneElement();

		if (null != ancestorRoles && ancestorRoles.size() > 0) {
			for (String ancestorRole : ancestorRoles) {
				if (!roleId.equalsIgnoreCase(ancestorRole)) {
					String hashedAncestorRole = this.hashingFunction.getSHA1HashValue(ancestorRole);
					BigInteger hashedAncestorRoleVal = getBigIntegerValOfString(hashedAncestorRole);
					Element temp = getZr().newElement();
					temp.set(hashedAncestorRoleVal);
					multiplicatedValue2 = multiplicatedValue2.mulZn(temp);
					multiplicatedValue1 = multiplicatedValue1.mulZn(getS().add(temp));
				}
			}
		}

		Element termSubstraction = multiplicatedValue1.sub(multiplicatedValue2);
		Element sInverse = getS().invert();

		Element PiMs = sInverse.mulZn(termSubstraction);

		Element g = getG();
		Element gPiMs = g.powZn(PiMs);
		return gPiMs;
	}

	private Element computeAux2Value(String roleId, String userId) {
		Element multiplicatedValue = getZr().newOneElement();
		ArrayList<String> roleUserList = this.roleUserMap.get(roleId);

		if (null != roleUserList && roleUserList.size() > 0) {
			for (String roleUserId : roleUserList) {
				if (!userId.equalsIgnoreCase(roleUserId)) {
					String hashedRoleUserId = this.hashingFunction.getSHA1HashValue(roleUserId);
					BigInteger hashedRoleUserIdVal = getBigIntegerValOfString(hashedRoleUserId);
					Element temp = getZr().newElement();
					temp.set(hashedRoleUserIdVal);
					multiplicatedValue = multiplicatedValue.mulZn(temp);
				}
			}
		}

		return multiplicatedValue;
	}

	private Element computeAux1Value(String roleId) {
		ArrayList<String> ancestorRoles = this.roleManager.getRoleMap().get(roleId);
		Element multiplicatedValue = getZr().newOneElement();

		if (null != ancestorRoles && ancestorRoles.size() > 0) {
			for (String ancestorRole : ancestorRoles) {
				if (!roleId.equalsIgnoreCase(ancestorRole)) {
					String hashedAncestorRole = this.hashingFunction.getSHA1HashValue(ancestorRole);
					BigInteger hashedAncestorRoleVal = getBigIntegerValOfString(hashedAncestorRole);
					Element temp = getZr().newElement();
					temp.set(hashedAncestorRoleVal);
					multiplicatedValue = multiplicatedValue.mulZn(temp);
				}
			}
		}

		return multiplicatedValue;
	}

	private Element computeDValue(String roleId, String location) {
		Element Ti = getRoleUserParameters().get(roleId).get("Ti").duplicate();
		// System.out.println("Ti =" + Ti);

		byte[] c3Bytes = this.messageCipherMap.get(location).get("C3");
		Element C3 = getG1().newElement();
		C3.setFromBytes(c3Bytes);
		// System.out.println("C3 =" + C3 );

		Element D = this.pairing.pairing(Ti, C3);
		// System.out.println("D in System Admin = " + D);
		return D;
	}

	/**
	 * @param string
	 * @return This method converts string value to a BigInteger Value
	 */
	public BigInteger getBigIntegerValOfString(String string) {
		BigInteger bigInt = null;
		try {
			bigInt = new BigInteger(string.getBytes("us-ascii"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return bigInt;
	}

	/*
	 * This method sends RolePublicParameters map over the network
	 */
	@Override
	public HashMap<String, byte[]> getRolePublicParameters(String roleId) throws RemoteException {
		HashMap<String, byte[]> myMap = new HashMap<String, byte[]>();
		HashMap<String, Element> pubParameters = this.rolePublicParameters.get(roleId);
		for (Entry<String, Element> entry : pubParameters.entrySet()) {
			myMap.put(entry.getKey(), entry.getValue().toBytes());
		}
		return myMap;
	}

	/*
	 * This method sends Public Key map over the network
	 */
	@Override
	public HashMap<String, byte[]> getPublicKey() throws RemoteException {
		HashMap<String, byte[]> myMap = new HashMap<String, byte[]>();
		HashMap<String, Element> pkParameters = this.pk;
		for (Entry<String, Element> entry : pkParameters.entrySet()) {
			myMap.put(entry.getKey(), entry.getValue().toBytes());
		}
		return myMap;
	}

	/*
	 * This method sends Master Key map over the network
	 */
	@Override
	public HashMap<String, byte[]> getMasterKey() throws RemoteException {
		HashMap<String, byte[]> myMap = new HashMap<String, byte[]>();
		HashMap<String, Element> mkParameters = this.mk;
		for (Entry<String, Element> entry : mkParameters.entrySet()) {
			myMap.put(entry.getKey(), entry.getValue().toBytes());
		}
		return myMap;
	}

	/*
	 * This method sets Role Cipher text which is received from Owner over the
	 * network
	 */
	@Override
	public void setRoleCipherText(String roleId, HashMap<String, byte[]> cipherParts, String locationPath)
			throws RemoteException {
		HashMap<String, Element> myHashMap = new HashMap<String, Element>();
		for (Entry<String, byte[]> entry : cipherParts.entrySet()) {
			Element temp = getG1().newElement();
			temp.setFromBytes(entry.getValue());
			myHashMap.put(entry.getKey(), temp);
		}
		this.roleCipherText.put(roleId, myHashMap);
		this.messageCipherMap.put(locationPath, cipherParts);
	}

	/*
	 * This method sends RoleUserParameters (Ki,Ti,Wi,Vi,Si,IDr) converted into
	 * a Byte to send over the network
	 */
	@Override
	public HashMap<String, byte[]> getRoleUserParametersInBytes(String roleId) throws RemoteException {
		HashMap<String, byte[]> myMap = new HashMap<String, byte[]>();
		HashMap<String, Element> roleUserParameter = this.roleUserParameters.get(roleId);
		for (Entry<String, Element> entry : roleUserParameter.entrySet()) {
			myMap.put(entry.getKey(), entry.getValue().toBytes());
		}
		return myMap;
	}

	@Override
	public void addPairToKeyMap(String roleId, String location, String encKey) throws RemoteException {
		ArrayList<String> pair = new ArrayList<String>();
		pair.add(roleId);
		pair.add(encKey);
		getKeyMap().put(location, pair);
	}

	/*
	 * This method sends cipher parts (C1,C2,C3) of a location which is used to
	 * compute decryption key for that particular location.
	 */
	@Override
	public HashMap<String, byte[]> getLocationCipher(String location) throws RemoteException {
		return this.messageCipherMap.get(location);
	}

	public Element getW() {
		return w.duplicate();
	}

	public Element getV() {
		return v.duplicate();
	}

	public Field getZr() {
		return Zr;
	}

	@Override
	public Element getG() {
		return g.duplicate();
	}

	@Override
	public Element getS() {
		return s.duplicate();
	}

	public Element getH() {
		return h.duplicate();
	}

	public Element getK() {
		return k.duplicate();
	}

	public Field getG1() {
		return G1;
	}

	public Field getG2() {
		return G2;
	}

	public Field getGT() {
		return GT;
	}

	public HashMap<String, HashMap<String, Element>> getRoleUserParameters() {
		return roleUserParameters;
	}

	public HashMap<String, HashMap<String, Element>> getRoleCipherText() {
		return roleCipherText;
	}

	public HashMap<String, Element> getMk() {
		return mk;
	}

	public HashMap<String, Element> getPk() {
		return pk;
	}

	public HashMap<String, ArrayList<String>> getRoleUserMap() {
		return roleUserMap;
	}

	public HashMap<String, ArrayList<String>> getKeyMap() {
		return keyMap;
	}

	public void setKeyMap(HashMap<String, ArrayList<String>> keyMap) {
		this.keyMap = keyMap;
	}

	public LinkedHashMap<String, ArrayList<String>> getRoleMap() {
		return roleMap;
	}

	public void setRoleMap(LinkedHashMap<String, ArrayList<String>> roleMap) {
		this.roleMap = roleMap;
	}

	/**
	 * @return singleton system administrator instance.
	 */
	public static RemoteSystemAdministratorImpl getRemoteSystemAdministratorImplInstance() {
		if (null == remoteSystemAdministratorImpl) {
			try {
				remoteSystemAdministratorImpl = new RemoteSystemAdministratorImpl();
			} catch (RemoteException e) {
				e.printStackTrace();
			}
		}
		return remoteSystemAdministratorImpl;
	}

}
