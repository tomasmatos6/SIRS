package pt.ulisboa.tecnico.meic.sirs;

import javax.crypto.Cipher;

public class ImageRSACipher {

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("This program encrypts an image file with RSA.");
            System.err.println("Usage: image-rsa-cipher [inputFile.png] [publicKeyFile] outputFile.png]");
            return;
        }

        final String inputFile = args[0];
        final String keyFile = args[1];
        final String outputFile = args[2];

        RSACipherByteArrayMixer cipher = new RSACipherByteArrayMixer(Cipher.ENCRYPT_MODE);
        cipher.setParameters(keyFile);
        ImageMixer.mix(inputFile, outputFile, cipher);
    }
}
