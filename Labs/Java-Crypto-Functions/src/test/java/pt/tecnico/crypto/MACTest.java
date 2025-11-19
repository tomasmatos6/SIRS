package pt.tecnico.crypto;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

/**
 * Test suite to show how the Java Security API can be used for MAC (Message Authentication Codes)
 * with nonce-based replay attack detection, tamper detection, and performance comparison.
 */
public class MACTest {

  /** Plain text to protect with the message authentication code. */
  final String plainText = "This is the plain text!";

  /** Plain text bytes. */
  final byte[] plainBytes = plainText.getBytes();

  // --- Symmetric Algorithm Constants ---
  /** Symmetric cryptography algorithm. */
  private static final String SYM_ALGO = "AES";

  /** Symmetric algorithm key size. */
  private static final int SYM_KEY_SIZE = 128;

  /** Symmetric cipher: combination of algorithm, block processing, and padding. */
  private static final String SYM_CIPHER = "AES/ECB/PKCS5Padding";

  // --- Asymmetric Algorithm Constants ---
  /** Asymmetric cryptography algorithm. */
  private static final String ASYM_ALGO = "RSA";

  /** Asymmetric algorithm key size. */
  private static final int ASYM_KEY_SIZE = 2048;

  /** Asymmetric cipher: combination of algorithm, block processing, and padding. */
  private static final String ASYM_CIPHER = "RSA/ECB/PKCS1Padding";

  // --- MAC and Digest Constants ---
  /** Message authentication code algorithm. */
  private static final String MAC_ALGO = "HmacSHA256";

  /** Digest algorithm. */
  private static final String DIGEST_ALGO = "SHA-256";

  // --- Performance Test Constants ---
  /**
   * Data size for performance test. Note: RSA with 2048-bit key and PKCS1Padding can encrypt max
   * 245 bytes. (2048 bits / 8 bytes/bit) - 11 bytes padding = 245 bytes.
   */
  private static final int PERF_TEST_DATA_SIZE = 128;

  // --- Nonce Management (for Requirement 3) ---
  private static final long MAX_TIME_DELTA_MS = 300000; // 5 minute tolerance
  private static long lastSentCounter = 0; // Persistent counter for message numbering (Sender)
  private static long lastReceivedCounter =
      0; // Persistent counter for message numbering (Receiver)
  private static long lastReceivedTimestamp = 0; // Persistent timestamp for replay (Receiver)
  private static Set<Long> nonceSet = new TreeSet<Long>();
  private static Long nonce;

  /** Nonce generation strategies */
  public enum NonceType {
    TIMESTAMP,
    COUNTER,
    NONCE,
    HYBRID
  }

  /** Generate a nonce based on selected strategy */
  private static byte[] generateNonce(NonceType type) {
    ByteBuffer nonceBuffer = ByteBuffer.allocate(16); // 16 bytes for nonce

    switch (type) {
      case TIMESTAMP:
        long timestamp = System.currentTimeMillis();
        nonceBuffer.putLong(timestamp);
        nonceBuffer.putLong(0); // Padding
        break;

      case COUNTER:
        lastSentCounter++;
        nonceBuffer.putLong(lastSentCounter);
        nonceBuffer.putLong(0); // Padding
        break;

      case NONCE:
        SecureRandom r = new SecureRandom();
        nonce = r.nextLong();
        while (nonceSet.contains(nonce)) nonce = r.nextLong();
        nonceSet.add(nonce);
        nonceBuffer.putLong(nonce);
        nonceBuffer.putLong(0);
        break;

      case HYBRID:
        // First 8 bytes: timestamp
        nonceBuffer.putLong(System.currentTimeMillis());
        // Next 8 bytes: counter
        lastSentCounter++;
        nonceBuffer.putLong(lastSentCounter);
        break;
    }

    return nonceBuffer.array();
  }

  /** Verify nonce freshness * @return true if nonce is fresh (not replayed) */
  private static boolean verifyNonceFreshness(byte[] receivedNonce, NonceType type) {
    ByteBuffer nonceBuffer = ByteBuffer.wrap(receivedNonce);
    long receivedValue = nonceBuffer.getLong();

    long currentTime;
    long timeDelta;

    switch (type) {
      case TIMESTAMP:
        currentTime = System.currentTimeMillis();
        timeDelta = Math.abs(currentTime - receivedValue);

        // Check 1: Freshness (within acceptable window)
        if (timeDelta > MAX_TIME_DELTA_MS) {
          return false;
        }

        // Check 2: Replay (must be newer than last received)
        if (receivedValue <= lastReceivedTimestamp) {
          return false; // Replay attack detected
        }

        lastReceivedTimestamp = receivedValue;
        return true;

      case COUNTER:
        // Ensure counter is greater than last seen
        if (receivedValue <= lastReceivedCounter) {
          return false; // Replay attack detected
        }
        lastReceivedCounter = receivedValue;
        return true;

      case NONCE:
        if (nonceSet.contains(receivedValue)) {
          return false;
        }
        nonceSet.add(receivedValue);
        return true;

      case HYBRID:
        // Verify timestamp first
        long receivedTimestamp = receivedValue;
        currentTime = System.currentTimeMillis();
        timeDelta = Math.abs(currentTime - receivedTimestamp);
        if (timeDelta > MAX_TIME_DELTA_MS) {
          return false; // Too old or future timestamp
        }
        // Then verify counter
        long receivedCounter = nonceBuffer.getLong();
        if (receivedCounter <= lastReceivedCounter) {
          return false; // Replay attack detected
        }
        lastReceivedCounter = receivedCounter;
        return true;
    }

    return false; // Add default return
  }

  /** Prepends nonce to message */
  private static byte[] prependNonce(byte[] message, byte[] nonce) {
    ByteBuffer combined = ByteBuffer.allocate(nonce.length + message.length);
    combined.put(nonce);
    combined.put(message);
    return combined.array();
  }

  /** Extracts nonce from combined message */
  private static byte[] extractNonce(byte[] combinedMessage) {
    return Arrays.copyOfRange(combinedMessage, 0, 16);
  }

  /** Extracts original message from combined message */
  private static byte[] extractMessage(byte[] combinedMessage) {
    return Arrays.copyOfRange(combinedMessage, 16, combinedMessage.length);
  }

  /**
   * Generate a Message Authentication Code using the Mac object with nonce and test replay
   * detection. This test fulfills REQ 3.
   */
  @Test
  public void testMACObjectWithNonceAndReplay() throws Exception {
    System.out.print("TEST '");
    System.out.print(MAC_ALGO);
    System.out.println("' message authentication code with NONCE (REQ 3).");

    System.out.println("Text:");
    System.out.println(plainText);
    System.out.println("Bytes:");
    System.out.println(printHexBinary(plainBytes));

    // Test with different nonce strategies
    // Reset counters for each independent test run
    lastSentCounter = 0;
    lastReceivedCounter = 0;
    lastReceivedTimestamp = 0;
    testWithNonce(NonceType.TIMESTAMP);

    lastSentCounter = 0;
    lastReceivedCounter = 0;
    lastReceivedTimestamp = 0;
    testWithNonce(NonceType.COUNTER);

    lastSentCounter = 0;
    lastReceivedCounter = 0;
    lastReceivedTimestamp = 0;
    testWithNonce(NonceType.HYBRID);

    System.out.println();
    System.out.println();
  }

  private void testWithNonce(NonceType nonceType) throws Exception {
    System.out.println("\n--- Testing with " + nonceType + " nonce ---");

    // generate AES secret key
    SecretKey key = generateMACKey(SYM_KEY_SIZE);

    // Generate and prepend nonce
    byte[] nonce = generateNonce(nonceType);
    byte[] messageWithNonce = prependNonce(plainBytes, nonce);

    System.out.print("Nonce: ");
    System.out.println(printHexBinary(nonce));
    System.out.print("Message with nonce: ");
    System.out.println(printHexBinary(messageWithNonce));

    // make MAC
    System.out.println("Signing...");
    byte[] macBytes = makeMAC(messageWithNonce, key);
    System.out.println("MAC:");
    System.out.println(printHexBinary(macBytes));

    // Simulate sending: MAC + original message
    // In real protocol, you'd send: MAC || nonce || message

    // verify the MAC
    System.out.println("Verifying...");
    boolean macValid = verifyMAC(macBytes, messageWithNonce, key);

    // Extract and verify nonce freshness
    byte[] extractedNonce = extractNonce(messageWithNonce);
    boolean nonceFresh = verifyNonceFreshness(extractedNonce, nonceType);

    System.out.println("MAC is " + (macValid ? "valid" : "invalid"));
    System.out.println("Nonce is " + (nonceFresh ? "fresh" : "replayed"));

    boolean result = macValid && nonceFresh;
    System.out.println("Overall verification: " + (result ? "SUCCESS" : "FAILURE"));
    assertTrue(result);

    // Test replay attack detection
    System.out.println("\n--- Testing replay attack detection ---");
    // We re-use the *exact same nonce* (extractedNonce)
    // The `verifyNonceFreshness` function should now return false
    boolean replayDetected = !verifyNonceFreshness(extractedNonce, nonceType);
    System.out.println("Replay attack " + (replayDetected ? "detected" : "not detected"));
    assertTrue(replayDetected, "Replay should be detected"); // Swapped arguments
  }

  /** Test the Tamper Detection of the MAC. This test fulfills REQ 2. */
  @Test
  public void testMACTampering() throws Exception {
    System.out.println("TEST MAC Tamper Detection (REQ 2)");

    // 1. Generate key, message, and valid MAC
    SecretKey key = generateMACKey(SYM_KEY_SIZE);
    byte[] message = "This is a clean message.".getBytes();
    byte[] mac = makeMAC(message, key);

    System.out.println("Original Message: " + new String(message));
    System.out.println("Original MAC: " + printHexBinary(mac));

    // 2. Tamper with the message
    byte[] tamperedMessage = message.clone();
    tamperedMessage[tamperedMessage.length - 1]++; // Flip one bit
    System.out.println("Tampered Message: " + new String(tamperedMessage));

    // 3. Verify the *original* MAC against the *tampered* message
    System.out.println("Verifying original MAC against tampered message...");
    boolean verificationResult = verifyMAC(mac, tamperedMessage, key);

    // 4. Assert that verification FAILED
    System.out.println(
        "Verification result: "
            + (verificationResult ? "SUCCESS" : "FAILURE (Tampering Detected!)"));
    assertFalse(verificationResult, "MAC verification should fail for tampered data.");

    System.out.println();
    System.out.println();
  }

  /**
   * Generate a Message Authentication Code by performing all the steps separately with nonce
   * support.
   */
  @Test
  public void testSignatureStepByStepWithNonce() throws Exception {
    System.out.print("TEST step-by-step MAC with NONCE using cipher '");
    System.out.print(SYM_CIPHER);
    System.out.print("' and digest '");
    System.out.print(DIGEST_ALGO);
    System.out.println("'");

    System.out.println("Text:");
    System.out.println(plainText);
    System.out.println("Bytes:");
    System.out.println(printHexBinary(plainBytes));

    // generate AES secret key
    SecretKey key = generateMACKey(SYM_KEY_SIZE);

    // make MAC with nonce
    System.out.println("Signing with nonce...");
    // Reset counter for this test
    lastSentCounter = 0;
    lastReceivedCounter = 0;
    byte[] nonce = generateNonce(NonceType.HYBRID);
    byte[] cipherDigest = digestAndCipherWithNonce(plainBytes, key, nonce);
    System.out.println("CipherDigest with nonce:");
    System.out.println(printHexBinary(cipherDigest));

    // verify the MAC
    System.out.println("Verifying...");
    boolean result = redigestDecipherAndCompareWithNonce(cipherDigest, plainBytes, key, nonce);
    System.out.println("MAC is " + (result ? "right" : "wrong"));
    assertTrue(result);

    System.out.println();
    System.out.println();
  }

  /**
   * Measure and compare operation times for Symmetric (AES) and Asymmetric (RSA) cryptography. This
   * test fulfills REQ 4.
   */
  @Test
  public void testPerformanceComparison() throws Exception {
    System.out.println("TEST Performance Comparison (AES vs RSA) (REQ 4)");

    // Generate random data for encryption
    byte[] data = new byte[PERF_TEST_DATA_SIZE];
    new SecureRandom().nextBytes(data);
    System.out.println("Testing with data size: " + PERF_TEST_DATA_SIZE + " bytes.");

    long startTime, endTime;
    long aesKeyGenTime, aesEncryptTime, aesDecryptTime;
    long rsaKeyGenTime, rsaEncryptTime, rsaDecryptTime;

    // --- AES (Symmetric) Performance ---
    System.out.println("\nRunning AES-" + SYM_KEY_SIZE + "...");

    // 1. AES Key Generation
    startTime = System.nanoTime();
    KeyGenerator aesKeyGen = KeyGenerator.getInstance(SYM_ALGO);
    aesKeyGen.init(SYM_KEY_SIZE);
    SecretKey aesKey = aesKeyGen.generateKey();
    endTime = System.nanoTime();
    aesKeyGenTime = (endTime - startTime) / 1_000; // Convert nano to milli

    // 2. AES Encryption
    Cipher aesCipher = Cipher.getInstance(SYM_CIPHER);
    startTime = System.nanoTime();
    aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
    byte[] aesEncryptedData = aesCipher.doFinal(data);
    endTime = System.nanoTime();
    aesEncryptTime = (endTime - startTime) / 1_000; // Convert nano to milli

    // 3. AES Decryption
    startTime = System.nanoTime();
    aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
    byte[] aesDecryptedData = aesCipher.doFinal(aesEncryptedData);
    endTime = System.nanoTime();
    aesDecryptTime = (endTime - startTime) / 1_000; // Convert nano to milli

    // Verify AES
    assertTrue(Arrays.equals(data, aesDecryptedData), "AES decryption failed");

    // --- RSA (Asymmetric) Performance ---
    System.out.println("Running RSA-" + ASYM_KEY_SIZE + "...");

    // 1. RSA Key Generation
    startTime = System.nanoTime();
    KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance(ASYM_ALGO);
    rsaKeyGen.initialize(ASYM_KEY_SIZE);
    KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();
    PublicKey rsaPublicKey = rsaKeyPair.getPublic();
    PrivateKey rsaPrivateKey = rsaKeyPair.getPrivate();
    endTime = System.nanoTime();
    rsaKeyGenTime = (endTime - startTime) / 1_000; // Convert nano to milli

    // 2. RSA Encryption
    Cipher rsaCipher = Cipher.getInstance(ASYM_CIPHER);
    startTime = System.nanoTime();
    rsaCipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
    byte[] rsaEncryptedData = rsaCipher.doFinal(data);
    endTime = System.nanoTime();
    rsaEncryptTime = (endTime - startTime) / 1_000; // Convert nano to milli

    // 3. RSA Decryption
    startTime = System.nanoTime();
    rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
    byte[] rsaDecryptedData = rsaCipher.doFinal(rsaEncryptedData);
    endTime = System.nanoTime();
    rsaDecryptTime = (endTime - startTime) / 1_000; // Convert nano to milli

    // Verify RSA
    assertTrue(Arrays.equals(data, rsaDecryptedData), "RSA decryption failed");

    // --- Print Results Table ---
    System.out.println("\n--- Performance Results (in milliseconds) ---");
    System.out.println("---------------------------------------------------------");
    System.out.printf(
        "| %-15s | %-15s | %-15s |\n", "Operation", "AES-" + SYM_KEY_SIZE, "RSA-" + ASYM_KEY_SIZE);
    System.out.println("---------------------------------------------------------");
    System.out.printf(
        "| %-15s | %-15d | %-15d |\n", "Key Generation", aesKeyGenTime, rsaKeyGenTime);
    System.out.printf("| %-15s | %-15d | %-15d |\n", "Encryption", aesEncryptTime, rsaEncryptTime);
    System.out.printf("| %-15s | %-15d | %-15d |\n", "Decryption", aesDecryptTime, rsaDecryptTime);
    System.out.println("---------------------------------------------------------");

    System.out.println();
    System.out.println();
  }

  // --- Helper Methods (Original) ---

  /** Generates a SecretKey for using in message authentication code. */
  private static SecretKey generateMACKey(int keySize) throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance(SYM_ALGO);
    keyGen.init(keySize);
    SecretKey key = keyGen.generateKey();

    return key;
  }

  /** Makes a message authentication code. */
  private static byte[] makeMAC(byte[] bytes, SecretKey key) throws Exception {
    Mac mac = Mac.getInstance(MAC_ALGO);
    mac.init(key);
    byte[] macBytes = mac.doFinal(bytes);

    return macBytes;
  }

  /** Calculates new digest from text and compare it to the to deciphered digest. */
  private static boolean verifyMAC(byte[] receivedMacBytes, byte[] bytes, SecretKey key)
      throws Exception {
    Mac mac = Mac.getInstance(MAC_ALGO);
    mac.init(key);
    byte[] recomputedMacBytes = mac.doFinal(bytes);
    return Arrays.equals(receivedMacBytes, recomputedMacBytes);
  }

  /** auxiliary method to calculate digest from text and cipher it with nonce */
  private static byte[] digestAndCipherWithNonce(byte[] bytes, SecretKey key, byte[] nonce)
      throws Exception {

    // Combine nonce with message
    byte[] messageWithNonce = prependNonce(bytes, nonce);

    // get a message digest object using the specified algorithm
    MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);

    // calculate the digest and print it out
    messageDigest.update(messageWithNonce);
    byte[] digest = messageDigest.digest();
    System.out.println("Digest:");
    System.out.println(printHexBinary(digest));

    // get an AES cipher object
    Cipher cipher = Cipher.getInstance(SYM_CIPHER);

    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] cipherDigest = cipher.doFinal(digest);

    return cipherDigest;
  }

  /**
   * auxiliary method to calculate new digest from text and compare it to the deciphered digest with
   * nonce
   */
  private static boolean redigestDecipherAndCompareWithNonce(
      byte[] cipherDigest, byte[] bytes, SecretKey key, byte[] nonce) throws Exception {

    // Combine nonce with message for recomputation
    byte[] messageWithNonce = prependNonce(bytes, nonce);

    // get a message digest object using the specified algorithm
    MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);

    // calculate the digest and print it out
    messageDigest.update(messageWithNonce);
    byte[] digest = messageDigest.digest();
    System.out.println("New digest:");
    System.out.println(printHexBinary(digest));

    // get an AES cipher object
    Cipher cipher = Cipher.getInstance(SYM_CIPHER);

    // decipher digest using the public key
    cipher.init(Cipher.DECRYPT_MODE, key);
    byte[] decipheredDigest = cipher.doFinal(cipherDigest);
    System.out.println("Deciphered Digest:");
    System.out.println(printHexBinary(decipheredDigest));

    // compare digests
    if (digest.length != decipheredDigest.length) return false;

    for (int i = 0; i < digest.length; i++) if (digest[i] != decipheredDigest[i]) return false;
    return true;
  }
}
