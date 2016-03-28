package aveugle;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Scanner;

import org.bouncycastle.crypto.engines.RSABlindingEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSABlindingFactorGenerator;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

public class Blinding_Signature {
	
	public static void main(String[] args) {
		
		try {
			//g�n�ration de la paire de cl�s
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.generateKeyPair();
			
			PublicKey pubKey = kp.getPublic();
			PrivateKey privKey = kp.getPrivate();
			
			//stockage de la cl� publique dans pub.key
			KeyFactory keyFact = KeyFactory.getInstance("RSA");
			
			RSAPublicKeySpec RSAKeySpec = keyFact.getKeySpec(pubKey, RSAPublicKeySpec.class);
			BigInteger PubMod = RSAKeySpec.getModulus();
			BigInteger PubExp = RSAKeySpec.getPublicExponent();
						
			FileOutputStream fosPub = new FileOutputStream("pub.key");		
			ObjectOutputStream oosPub = new ObjectOutputStream(fosPub);
			oosPub.writeObject(PubMod);
			oosPub.writeObject(PubExp);
			
			//stockage de la cl� priv�e dans priv.key
			RSAPrivateKeySpec RSAPrivKeySpec = keyFact.getKeySpec(privKey, RSAPrivateKeySpec.class);
			BigInteger PrivMod = RSAPrivKeySpec.getModulus();			
			BigInteger PrivExp = RSAPrivKeySpec.getPrivateExponent();	
			
			FileOutputStream fosPriv = new FileOutputStream("priv.key");	
			ObjectOutputStream oosPriv = new ObjectOutputStream(fosPriv);
			oosPriv.writeObject(PrivMod);
			oosPriv.writeObject(PrivExp);
			
			//r�trouver la cl� publique
			FileInputStream fisPub = new FileInputStream("pub.key");//byte [] bytePub = new byte [fisPub.available()];	//fisPub.read(bytePub);
		    ObjectInputStream oisPub = new ObjectInputStream(fisPub);
		       
		    BigInteger PubModulus = (BigInteger) oisPub.readObject();
		    BigInteger PubExponent = (BigInteger) oisPub.readObject();
		    
			//r�trouver la cl� priv�e
			FileInputStream fisPriv = new FileInputStream("priv.key"); //byte [] bytePriv = new byte [fisPriv.available()];	fisPriv.read(bytePriv);
			ObjectInputStream oisPriv = new ObjectInputStream(fisPriv);
			
			BigInteger PrivModulus = (BigInteger) oisPriv.readObject();
			BigInteger PrivExponent = (BigInteger) oisPriv.readObject();
			
			Scanner sc = new Scanner(System.in);
			System.out.print("Entrer le message � signer : ");
			byte[] tobeBlinded = sc.nextLine().getBytes();//"Crypto Avancee M2SSI".getBytes();
			System.out.println("Message initial : \n"+Arrays.toString(tobeBlinded));
			
			//Cl� Publique KeyParameters
			RSAKeyParameters RSAKeyParamPub = new RSAKeyParameters(false, PubModulus, PubExponent);
			//Cl� Priv�e KeyParameters			
			RSAKeyParameters RSAKeyParamPriv = new RSAKeyParameters(true, PrivModulus, PrivExponent);////
						
			RSABlindingFactorGenerator RSABlindFactGen = new RSABlindingFactorGenerator();
			RSABlindFactGen.init(RSAKeyParamPub);			
			BigInteger blindingFactor = RSABlindFactGen.generateBlindingFactor();
			
			//Brouillage
			RSABlindingParameters RSABlindParam = new RSABlindingParameters(RSAKeyParamPub, blindingFactor);
			RSABlindingEngine RSABlingEngine = new RSABlindingEngine();
			RSABlingEngine.init(true, RSABlindParam); //true for encryption
						
			byte[] blinded = RSABlingEngine.processBlock(tobeBlinded, 0, tobeBlinded.length); 
			
			System.out.println("Brouillage : \n"+Arrays.toString(blinded));
			
			//Signature du message Brouill�
			RSAEngine sign = new RSAEngine();
			sign.init(true, RSAKeyParamPriv);
			
			byte [] blindedSign = sign.processBlock(blinded, 0, blinded.length);
			System.out.println("Signature : \n"+Arrays.toString(blindedSign));
			
			//D�brouillage du message Sign�
			RSABlindingParameters RSAUnblindParam = new RSABlindingParameters(RSAKeyParamPriv, blindingFactor);
			RSABlindingEngine RSAUnblindEngine = new RSABlindingEngine();
			RSAUnblindEngine.init(false, RSAUnblindParam);			
			
			byte [] unBlindSign = RSAUnblindEngine.processBlock(blindedSign, 0, blindedSign.length);
			System.out.println("D�brouillage : \n"+Arrays.toString(unBlindSign));
			
			//V�rification de la Signature du message d�brouill�
			RSAEngine unsign = new RSAEngine();
			unsign.init(false, RSAKeyParamPub);
			byte [] unBlinded = unsign.processBlock(unBlindSign, 0, unBlindSign.length);
			
			System.out.println("V�rification de signature : \n"+Arrays.toString(unBlinded));
			System.out.println("V�rification du Texte signer : "+new String(unBlinded, "utf8"));
			
			fisPriv.close();
			fisPub.close();
			fosPriv.close();
			fosPub.close();
			oisPriv.close();
			oisPub.close();
			oosPriv.close();
			oosPub.close();			
		}
		catch (Exception e) {
			e.printStackTrace();
		}	
	}
}
