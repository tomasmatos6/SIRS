package pt.ulisboa.tecnico.meic.sirs;

import java.security.Key;

import javax.crypto.Cipher;

/**
 * Implementation of the RSA cipher as a ByteArrayMixer.
 * Reads the appropriate key type based on operation mode.
 */
public class RSACipherByteArrayMixer implements ByteArrayMixer {

    private String keyFile;
    private int opmode;

    public RSACipherByteArrayMixer(int opmode) {
        this.opmode = opmode;
    }

    public void setParameters(String keyFile) {
        this.keyFile = keyFile;
    }

    @Override
    public byte[] mix(byte[] byteArray, byte[] byteArray2) throws Exception {
        // Read the correct key type based on operation mode
        Key key;
        if (opmode == Cipher.ENCRYPT_MODE) {
            // Encryption uses public key
            key = RSAKeyGenerator.readPublicKey(keyFile);
        } else {
            // Decryption uses private key
            key = RSAKeyGenerator.readPrivateKey(keyFile);
        }
        
        // Get RSA cipher with PKCS1 padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        System.out.println(cipher.getProvider().getInfo());
        
        String operation = (opmode == Cipher.ENCRYPT_MODE) ? "Encrypting" : "Decrypting";
        System.out.println(operation + " ...");
        
        // No IV needed for RSA
        cipher.init(this.opmode, key);
        
        return cipher.doFinal(byteArray);
    }
}
