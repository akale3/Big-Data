package edu.user;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;

import edu.bigdata.algorithms.FileDecryption;
import edu.bigdata.algorithms.HashingFunction;
import edu.systemadministrator.RemoteSystemAdministrator;
import edu.systemadministrator.RoleManager;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class UserImpl {

	private RemoteSystemAdministrator systemAdministrator = null;
	private String userId = null;
	private Field G1 = null;

	public UserImpl(String userId, RemoteSystemAdministrator systemAdministrator) {
		this.userId = userId;
		this.systemAdministrator = systemAdministrator;
	}

	/**
	 * @param userId
	 *            - user Id of a user which is decrypting the key
	 * @param roleId
	 *            - role Id of that user
	 * @param location
	 *            - location which is need to be decrypted.
	 * 
	 * @return It decrypts images of given folder location. It takes cipher
	 *         parts from cloud and computes decryption keys based on these
	 *         cipher parts.
	 */
	public void decryptMessage(String userId, String roleId, String location) {

		long startTime = (int) System.currentTimeMillis();
		Pairing pairing = PairingFactory.getPairing("./resources/a.properties");
		this.G1 = pairing.getG1();

		System.out.println("User with User Id =" + userId + " having Role Id = " + roleId
				+ " trying to decrpyt location " + location);
		try {

			String roleIdEnc = systemAdministrator.getKeyMap().get(location).get(0);
			LinkedHashMap<String, ArrayList<String>> roleMap = systemAdministrator.getRoleMap();

			if (roleMap.containsKey(roleId) && null != roleMap.get(roleId)) {
				if (roleIdEnc.equalsIgnoreCase(roleId) || roleMap.get(roleId).contains(roleIdEnc)) {
					// get user secret key
					HashMap<String, byte[]> decriptionKeyParamMap = systemAdministrator.getDecriptionKeyParams(roleId,
							userId, location);

					String decryptionKey = generateDecpryptionKey(decriptionKeyParamMap, roleId, G1, location);

					decryptionKey = systemAdministrator.getKeyMap().get(location).get(1);
					System.out.println("Computed 128 bit Decryption Key = " + decryptionKey);

					long endTime = (int) System.currentTimeMillis();
					// System.out.println("Totaltime For Decryption Algorithm="
					// + (endTime - startTime) + "ms");

					FileDecryption fileDecryption = new FileDecryption();
					fileDecryption.decryptFile(decryptionKey, location + "Encrypted/");
				} else {
					System.out.println("The Role =" + roleId + " does not have access location = " + location);
				}
			} else {
				System.out.println("The Role =" + roleId + " does not have access location = " + location);
			}

		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	/**
	 * @param decriptionKeyParamMap
	 * @param roleId
	 * @param g1
	 * @param location
	 * @return This method computes decryption key parameters and decryption key
	 *         based on given input parameters
	 */
	private String generateDecpryptionKey(HashMap<String, byte[]> decriptionKeyParamMap, String roleId, Field g1,
			String location) {

		try {
			byte[] dkubytes = systemAdministrator.getDecryptionKey(userId);
			Element dku = g1.newElement();
			dku.setFromBytes(dkubytes);
			// System.out.println("dku=" + dku);

			// Compute ki
			Element ki = computeKi(decriptionKeyParamMap, dku, roleId, g1);
			// System.out.println("Ki = " + ki);

			// compute K- decryption key
			Element k = computeK(decriptionKeyParamMap, ki, roleId, g1, location);
			// System.out.println("Decryption Key =" + k);

			return k.toBigInteger().toString();
		} catch (RemoteException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param decriptionKeyParamMap
	 * @param ki
	 * @param roleId
	 * @param g1
	 * @param location
	 * @return This method computes final decryption key based on the input
	 *         parameter values.
	 */
	private Element computeK(HashMap<String, byte[]> decriptionKeyParamMap, Element ki, String roleId, Field g1,
			String location) {

		try {
			HashingFunction hashingFunction = new HashingFunction();
			Pairing pairing = PairingFactory.getPairing("./resources/a.properties");

			HashMap<String, byte[]> roleUserParam = systemAdministrator.getRoleUserParametersInBytes(roleId);

			Element Si = g1.newElement();
			Si.setFromBytes(roleUserParam.get("Si"));
			// System.out.println("Si= " + Si);

			Element gPims = g1.newElement();
			gPims.setFromBytes(decriptionKeyParamMap.get("gPiMs"));
			// System.out.println("gPims = " + gPims);

			HashMap<String, byte[]> messageCipherParts = systemAdministrator.getLocationCipher(location);
			Element C1 = g1.newElement();
			C1.setFromBytes(messageCipherParts.get("C1"));
			// System.out.println(" C1 = " + C1);

			Element C2 = g1.newElement();
			C2.setFromBytes(messageCipherParts.get("C2"));
			// System.out.println(" C2 = " + C2);

			Element C3 = g1.newElement();
			C3.setFromBytes(messageCipherParts.get("C3"));
			// System.out.println(" C3 = " + C3);

			Element Ti = g1.newElement();
			Ti.setFromBytes(roleUserParam.get("Ti"));
			// System.out.println("Ti= " + Ti);

			Element D = pairing.pairing(Ti, C3);
			// System.out.println("D in User= " + D);

			Element pairing1 = pairing.pairing(gPims, C1);
			// System.out.println("pairing1 = " + pairing1);

			String hashKi = hashingFunction.getSHA256HashValue(ki.toString());
			BigInteger hashKival = getBigIntegerValOfString(hashKi);
			Element kiElement = pairing.getZr().newElement();
			kiElement.set(hashKival);

			Element multiplicationPair = Si.mulZn(kiElement.invert());
			// System.out.println("multiplicationPair = " + multiplicationPair);

			Element pairing2 = pairing.pairing(multiplicationPair, C2);
			// System.out.println("pairing2 = " + pairing2);

			Element product = pairing1.mulZn(pairing2);
			// System.out.println("product = " + product);

			Element productWithD = product.mulZn(D);
			// System.out.println("productWithD = " + productWithD);

			Element Aux1 = pairing.getZr().newElement();
			Aux1.setFromBytes(decriptionKeyParamMap.get("Aux1"));
			Element Aux1Inverse = Aux1.invert();
			// System.out.println("Aux1 Inverse = " + Aux1Inverse);

			Element decryptionKey = productWithD.powZn(Aux1Inverse);
			return decryptionKey;
		} catch (RemoteException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param decriptionKeyParamMap
	 * @param dku
	 * @param roleId
	 * @param g1
	 * @return This method computes parameters which are required in generating
	 *         decryption key.
	 */
	private Element computeKi(HashMap<String, byte[]> decriptionKeyParamMap, Element dku, String roleId, Field g1) {

		Element Ki = null;
		try {
			HashMap<String, byte[]> roleUserParam = systemAdministrator.getRoleUserParametersInBytes(roleId);

			Element Wi = g1.newElement();
			Wi.setFromBytes(roleUserParam.get("Wi"));

			Element Vi = g1.newElement();
			Vi.setFromBytes(roleUserParam.get("Vi"));

			Pairing pairing = PairingFactory.getPairing("./resources/a.properties");

			Element firstTerm = pairing.pairing(Vi, dku);

			Element gPkNs = g1.newElement();
			gPkNs.setFromBytes(decriptionKeyParamMap.get("gPkNs"));

			Element secondTerm = pairing.pairing(gPkNs, Wi);
			Element multiplication = firstTerm.mulZn(secondTerm);

			Element Aux2 = pairing.getZr().newElement();
			Aux2.setFromBytes(decriptionKeyParamMap.get("Aux2"));
			Element Aux2Inverse = Aux2.invert();
			// System.out.println("Aux2Inverse = " + Aux2Inverse );

			Ki = multiplication.powZn(Aux2Inverse);
		} catch (RemoteException e) {
			e.printStackTrace();
		}
		return Ki;
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
