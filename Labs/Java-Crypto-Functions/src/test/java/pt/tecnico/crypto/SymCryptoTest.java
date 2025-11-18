package pt.tecnico.crypto;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static java.util.stream.IntStream.range;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.Test;

public class SymCryptoTest {
	/** Plain text to cipher. */
	private final String plainText = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	/** Plain text bytes. */
	private final byte[] plainBytes = plainText.getBytes();

	/** Symmetric cryptography algorithm. */
	private static final String SYM_ALGO = "AES";
	/** Symmetric algorithm key size. */
	private static final int SYM_KEY_SIZE = 128;
	/**
	 * Symmetric cipher: combination of algorithm, block processing, and padding.
	 */
	private static final String SYM_CIPHER = "AES/ECB/PKCS5Padding";

	/**
	 * Secret key cryptography test.
	 * 
	 * @throws Exception because test is not concerned with exception handling
	 */
	@Test
	public void testSymCrypto() throws Exception {
		System.out.print("TEST '");
		System.out.print(SYM_CIPHER);
		System.out.println("'");

		System.out.println("Text:");
		System.out.println(plainText);
		System.out.println("Bytes:");
		System.out.println(printHexBinary(plainBytes));

		// get a AES private key
		System.out.println("GeneratingCBCC key...");
		KeyGenerator keyGen = KeyGenerator.getInstance(SYM_ALGO);
		keyGen.init(SYM_KEY_SIZE);
		Key key = keyGen.generateKey();
		System.out.print("Key: ");
		System.out.println(printHexBinary(key.getEncoded()));

		// get a AES cipher object and print the provider
		Cipher cipher = Cipher.getInstance(SYM_CIPHER);
		System.out.println(cipher.getProvider().getInfo());
		
		IvParameterSpec iv = null;
		if (SYM_CIPHER.contains("CBC")) {
			iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class);
		}

		// encrypt using the key and the plain text
		System.out.println("Ciphering...");
		if (SYM_CIPHER.contains("CBC")) 
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		else
			cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherBytes = cipher.doFinal(plainBytes);
		System.out.print("Result 0: ");
		System.out.println(printHexBinary(cipherBytes));
		
		if(SYM_CIPHER.contains("CBC")) {
			for(int i=0;i<2;i++) {
				cipherBytes = cipher.doFinal(cipherBytes);
				System.out.printf("Result %d: ", i+1);
				System.out.println(printHexBinary(cipherBytes));
			}
		}
		
		// decipher the cipher text using the same key
		System.out.println("Deciphering...");
		if (SYM_CIPHER.contains("CBC"))
			cipher.init(Cipher.DECRYPT_MODE, key, iv);
		else
			cipher.init(Cipher.DECRYPT_MODE, key);

		byte[] newPlainBytes = cipher.doFinal(cipherBytes);
		System.out.print("Result 0: ");
		System.out.println(printHexBinary(newPlainBytes));

		if(SYM_CIPHER.contains("CBC")) {
			for(int i=0;i<2;i++) {
				newPlainBytes = cipher.doFinal(newPlainBytes);
				System.out.printf("Result %d: ", i+1);
				System.out.println(printHexBinary(newPlainBytes));

			}
		}
		
		System.out.println("Text:");
		String newPlainText = new String(newPlainBytes);
		System.out.println(newPlainText);

		assertEquals(plainText, newPlainText);

		System.out.println();
		System.out.println();
	}
}
