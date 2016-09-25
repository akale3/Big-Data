package edu.owner;

import java.rmi.RemoteException;
import java.util.HashMap;

import edu.bigdata.algorithms.FileEncryption;
import edu.systemadministrator.RemoteSystemAdministrator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class OwnerImpl {

	RemoteSystemAdministrator systemAdministrator = null;
	Field g = null;
	Field zr = null;

	public OwnerImpl(RemoteSystemAdministrator systemAdministrator) {
		this.systemAdministrator = systemAdministrator;
	}

	/**
	 * @param roleId
	 *            - this is a role Id which Owner uses to encrypt a particular
	 *            location containing the images.
	 * @param locationPath
	 *            - location path of those images which is need to be encrypted
	 * 
	 * @return It encrypts images of given folder location. It puts cipher parts
	 *         on cloud.
	 */
	public void encryptMessage(String roleId, String locationPath) {

		HashMap<String, byte[]> rolePublicParamMap;
		HashMap<String, byte[]> publicKey;
		HashMap<String, byte[]> masterKey;

		System.out.println("Encryption Started for location " + locationPath + " Using role id = " + roleId);
		long startTime = (int) System.currentTimeMillis();
		try {
			rolePublicParamMap = systemAdministrator.getRolePublicParameters(roleId);

			Pairing pairing = PairingFactory.getPairing("./resources/a.properties");
			this.g = pairing.getG1();
			this.zr = pairing.getZr();

			// get already stored public parameters from cloud and computes
			// Encryption key and cipher text.

			Element Ar = g.newElement();
			Ar.setFromBytes(rolePublicParamMap.get("Ar"));
			// System.out.println("Ar" + Ar);

			Element Br = g.newElement();
			Br.setFromBytes(rolePublicParamMap.get("Br"));
			// System.out.println("Br" + Br);

			publicKey = systemAdministrator.getPublicKey();
			masterKey = systemAdministrator.getMasterKey();

			Element w = g.newElement();
			w.setFromBytes(publicKey.get("w"));
			// System.out.println("w" + w);

			Element z = zr.newRandomElement();
			// System.out.println("Z" + z);

			// Computing Cipher Text
			Element c1 = w.powZn(z.duplicate().negate());
			Element c1Duplicate = c1.duplicate();
			Element c2 = Ar.duplicate().powZn(z.duplicate());
			Element c3 = Br.duplicate().powZn(z.duplicate());

			// publishing cipher parts to cloud
			HashMap<String, byte[]> cipherParts = new HashMap<String, byte[]>();
			cipherParts.put("C1", c1Duplicate.toBytes());
			cipherParts.put("C2", c2.toBytes());
			cipherParts.put("C3", c3.toBytes());
			systemAdministrator.setRoleCipherText(roleId, cipherParts, locationPath);

			// Compute encryption key
			Element pubParaG = g.newElement();
			pubParaG.setFromBytes(publicKey.get("g"));

			Element pubParaH = g.newElement();
			pubParaH.setFromBytes(masterKey.get("h"));

			Element v = pairing.pairing(pubParaG, pubParaH);
			// System.out.println("Value of V in owner = " + v);

			Element encryptionKey = v.powZn(z.duplicate());
			// System.out.println("Encryption key="+encryptionKey);
			String encKey = encryptionKey.toBigInteger().toString().substring(0, 16);
			System.out.println("128 bit Encryption key=" + encKey);
			systemAdministrator.addPairToKeyMap(roleId, locationPath, encKey);

			long endTime = (int) System.currentTimeMillis();
			// System.out.println("Totaltime For Encryption Algorithm =" +
			// (endTime - startTime) + "ms");

			// Encrypts images of that particular location
			FileEncryption fileEncryption = new FileEncryption();
			fileEncryption.encryptFile(encKey, locationPath);

		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

}
