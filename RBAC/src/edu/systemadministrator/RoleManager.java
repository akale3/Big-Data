package edu.systemadministrator;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import edu.bigdata.algorithms.HashingFunction;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class RoleManager {

	private RemoteSystemAdministratorImpl systemAdministrator = null;
	private static RoleManager roleManager = null;
	public LinkedHashMap<String, ArrayList<String>> roleMap = null;
	public LinkedHashMap<String, HashMap<String, Element>> previousYiMap = new LinkedHashMap<String, HashMap<String, Element>>();

	private RoleManager() {

	}

	public void initialize() {
		this.systemAdministrator = RemoteSystemAdministratorImpl.getRemoteSystemAdministratorImplInstance();
	}

	/**
	 * @param userId
	 *            - user Id which is to be added in a particular role
	 * @param roleId
	 *            - Role Id in which user will be added
	 * 
	 * @return this method adds particular user in a particular role
	 */
	public void addUser(String userId, String roleId) {

		if (!systemAdministrator.getRoleUserMap().get(roleId).contains(userId)) {

			Element yiForSpecificRole = null;
			if (null != previousYiMap.get(roleId) && null != previousYiMap.get(roleId).get("yiForSpecificRole")) {
				yiForSpecificRole = previousYiMap.get(roleId).get("yiForSpecificRole");
			}

			Element previousYiForSpecificRole = null;
			if (null != previousYiMap.get(roleId)
					&& null != previousYiMap.get(roleId).get("previousYiForSpecificRole")) {
				previousYiForSpecificRole = previousYiMap.get(roleId).get("previousYiForSpecificRole");
			}

			if (null == yiForSpecificRole) {
				previousYiForSpecificRole = systemAdministrator.getG();
				yiForSpecificRole = computeYi(roleId, userId);
			} else {
				previousYiForSpecificRole = yiForSpecificRole;
				yiForSpecificRole = computeYi(roleId, userId);
			}

			HashMap<String, Element> paramMap;
			if (previousYiMap.get(roleId) == null) {
				paramMap = new HashMap<String, Element>();
			} else {
				paramMap = previousYiMap.get(roleId);
			}

			paramMap.put("previousYiForSpecificRole", previousYiForSpecificRole);
			paramMap.put("yiForSpecificRole", yiForSpecificRole);
			previousYiMap.put(roleId, paramMap);

			// compare two pairings to check if user can be added
			boolean isConditionTrue = compareTwoPairing(userId, roleId, yiForSpecificRole, previousYiForSpecificRole);
			if (isConditionTrue) {
				addUserToRoleList(userId, roleId);
			}
		} else {
			System.out.println("user already exist ");
		}

	}

	/**
	 * @param userId
	 * @param roleId
	 * @param Yi
	 * @param yiPrime
	 * @return It compares two terms based on given input and if the two
	 *         computed terms are euqlas it returns true value.
	 */
	private boolean compareTwoPairing(String userId, String roleId, Element Yi, Element yiPrime) {

		HashingFunction hashingFunction = new HashingFunction();
		Pairing pairing = PairingFactory.getPairing("./resources/a.properties");

		String hasedUserId = hashingFunction.getSHA1HashValue(userId);
		BigInteger hashedUserIdVal = getBigIntegerValOfString(hasedUserId);
		Element temp = systemAdministrator.getZr().newElement();
		temp.set(hashedUserIdVal);

		Element hH1Iduk = systemAdministrator.getH().powZn(temp);
		Element lhsFirstTerm = systemAdministrator.getW().mul(hH1Iduk);
		Element lhsPairing = pairing.pairing(yiPrime, lhsFirstTerm);
		Element rhsPairing = pairing.pairing(Yi, systemAdministrator.getH());

		if (lhsPairing.isEqual(rhsPairing)) {
			return true;
		}
		return false;
	}

	/**
	 * @param userId
	 * @param roleId
	 * 
	 * @return It adds particular user to a user list of a particular role
	 */
	private void addUserToRoleList(String userId, String roleId) {

		Element ri = null;
		Element ti = null;
		Element Yi = null;
		HashingFunction hashingFunction = new HashingFunction();
		HashMap<String, Element> paramMap = previousYiMap.get(roleId);

		if (null != paramMap && null != paramMap.get("ri")) {
			ri = paramMap.get("ri");
		}

		if (null != paramMap && null != paramMap.get("ti")) {
			ti = paramMap.get("ti");
		}

		if (null != paramMap && null != paramMap.get("yiForSpecificRole")) {
			Yi = paramMap.get("yiForSpecificRole");
		}

		if (null == ri && null == ti) {
			paramMap.put("ri", systemAdministrator.getZr().newRandomElement());
			paramMap.put("ti", systemAdministrator.getZr().newRandomElement());
			ri = previousYiMap.get(roleId).get("ri");
			ti = previousYiMap.get(roleId).get("ti");
		}

		Element Ki = systemAdministrator.getV().powZn(ri.duplicate());
		// System.out.println("Ki="+Ki);

		Element Ti = systemAdministrator.getG().powZn(ti.duplicate().negate());
		// System.out.println("Ti = " + Ti);

		Element Wi = systemAdministrator.getW().powZn(ri.duplicate().negate());
		// System.out.println("Wi = " + Wi);

		Element Vi = Yi.duplicate().powZn(ri.duplicate());
		// System.out.println("Vi = " + Vi);

		String hashedKi = hashingFunction.getSHA256HashValue(Ki.toString());
		BigInteger hashedKiValue = getBigIntegerValOfString(hashedKi);
		Element hashedKiValueElement = systemAdministrator.getZr().newElement();
		hashedKiValueElement.set(hashedKiValue);

		Element roleSecretKey = systemAdministrator.getRoleSecretKey(roleId);

		Element kTi = systemAdministrator.getK().mulZn(ti.duplicate());
		Element gkTi = systemAdministrator.getG().powZn(kTi);

		Element multSecondAndThird = gkTi.mul(roleSecretKey);

		Element Si = multSecondAndThird.mulZn(hashedKiValueElement);
		// System.out.println("This is value of Si = " + Si);

		// adding user id to RULRi (IDri, RULRi)
		systemAdministrator.getRoleUserMap().get(roleId).add(userId);
		previousYiMap.put(roleId, paramMap);

		// Publish tuple (IDr, Wi, Vi, Si, Ti) to cloud
		HashMap<String, Element> roleParameters = new HashMap<String, Element>();
		roleParameters.put("Wi", Wi);
		// System.out.println("Wi="+Wi);
		roleParameters.put("Vi", Vi);
		// System.out.println("V="+Vi);
		roleParameters.put("Si", Si);
		// System.out.println("si="+Si);
		roleParameters.put("Ti", Ti);
		// System.out.println("Ti="+Ti);

		systemAdministrator.getRoleUserParameters().put(roleId, roleParameters);

	}

	private Element computeYi(String roleId, String userId) {
		Element Yi = null;
		HashingFunction hashingFunction = new HashingFunction();
		Element multiplicatedValue = systemAdministrator.getZr().newOneElement();
		ArrayList<String> RULr = systemAdministrator.getRoleUserMap().get(roleId);
		if (null != RULr && !RULr.isEmpty()) {
			for (String roleUser : RULr) {
				String hasedRoleUserId = hashingFunction.getSHA1HashValue(roleUser);
				BigInteger roleUserIdVal = getBigIntegerValOfString(hasedRoleUserId);
				Element temp = systemAdministrator.getZr().newElement();
				temp.set(roleUserIdVal);
				Element addition;
				addition = systemAdministrator.getS().add(temp);
				multiplicatedValue = multiplicatedValue.mulZn(addition);
			}
		}

		String hasedUserId = hashingFunction.getSHA1HashValue(userId);
		BigInteger hashedUserIdVal = getBigIntegerValOfString(hasedUserId);
		Element temp = systemAdministrator.getZr().newElement();
		temp.set(hashedUserIdVal);

		Element addiWithS;
		addiWithS = systemAdministrator.getS().add(temp);
		Element multiplicationOfTwoTerms = addiWithS.mulZn(multiplicatedValue);

		Yi = systemAdministrator.getG().powZn(multiplicationOfTwoTerms);

		return Yi;
	}

	/**
	 * This method initializes roles of a system. This role hierarchy is added
	 * for local testing purpose.
	 */
	public void initializeRole() {
		roleMap = new LinkedHashMap<String, ArrayList<String>>();
		roleMap.put("RoleId1_12345678", new ArrayList<String>());
		roleMap.get("RoleId1_12345678").add("RoleId2_12345678");
		roleMap.get("RoleId1_12345678").add("RoleId3_12345678");
		roleMap.get("RoleId1_12345678").add("RoleId4_12345678");
		// roleMap.get("RoleId1_12345678").add("RoleId5_12345678");

		roleMap.put("RoleId2_12345678", new ArrayList<String>());
		roleMap.get("RoleId2_12345678").add("RoleId3_12345678");
		roleMap.get("RoleId2_12345678").add("RoleId4_12345678");
		// roleMap.get("RoleId2_12345678").add("RoleId5_12345678");

		roleMap.put("RoleId3_12345678", new ArrayList<String>());
		// roleMap.get("RoleId3_12345678").add("RoleId4_12345678");
		// roleMap.get("RoleId3_12345678").add("RoleId5_12345678");

		roleMap.put("RoleId4_12345678", new ArrayList<String>());
		// roleMap.get("RoleId4_12345678").add("RoleId5_12345678");

		// roleMap.put("RoleId5_12345678", new ArrayList<String>());
		systemAdministrator.setRoleMap(roleMap);

		printingRolesHierarchy(roleMap);
	}

	private void printingRolesHierarchy(LinkedHashMap<String, ArrayList<String>> roleMap2) {
		for (Map.Entry<String, ArrayList<String>> entry : roleMap2.entrySet()) {
			System.out.println(entry.getKey());
			ArrayList<String> InheritrdFrom = entry.getValue();
			for (String string : InheritrdFrom) {
				System.out.println("--> " + string);
			}
		}
	}

	public LinkedHashMap<String, ArrayList<String>> getRoleMap() {
		return roleMap;
	}

	public static RoleManager getRoleManagerInstance() {
		if (null == roleManager) {
			roleManager = new RoleManager();
		}
		return roleManager;
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

}
