package pt.tecnico;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class SecureReader {

  public static PublicKey readPublicKey(String keyPath) throws Exception {
    byte[] keyBytes = Files.readAllBytes(new File(keyPath).toPath());
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePublic(spec);
  }

  public static void main(String[] args) throws IOException {
    // Check arguments
    if (args.length < 2) {
      System.err.println("Argument(s) missing!");
      System.err.printf("Usage: java %s <outputFile> <publicKeyPath> <secretKey>%n",
          SecureReader.class.getName());
      return;
    }
    final String filename = args[0];
    final String keyPath = args[1];
    final String secretKeyPath = args[2] != null ? args[2] : "../../../keys/secret.key";

    // Read JSON object from file, and print its contets
    try (FileReader fileReader = new FileReader(filename)) {
      Gson gson = new Gson();
      JsonObject encryptedJson = gson.fromJson(fileReader, JsonObject.class);

      // --- Confidentiality verification ---
      if (!encryptedJson.has("secureJson")) {
        System.err.println("Error: File is not encrypted or format is wrong.");
        return;
      }

      String b64rootJson = encryptedJson.get("secureJson").getAsString();
      byte[] encryptedBytes = Base64.getDecoder().decode(b64rootJson);

      SecretKeySpec secretKey = CryptoUtils.readSecretKey(secretKeyPath);

      byte[] decryptedBytes = CryptoUtils.decrypt(secretKey, encryptedBytes);
      String decryptedString = new String(decryptedBytes);

      JsonObject rootJson = gson.fromJson(decryptedString, JsonObject.class);
      System.out.println("Decryption Successful. Analyzing content...");

      // --- Freshness verification ---
      if (!rootJson.has("timestamp")) {
        System.err.println("Security Error: Timestamp missing.");
        return;
      }
      long fileTimestamp = rootJson.get("timestamp").getAsLong();
      long currentTimestamp = System.currentTimeMillis();

      if (currentTimestamp - fileTimestamp > 30000) {
        System.err.println("Security Error: rootJson is not fresh.");
        return;
      }

      if (fileTimestamp > currentTimestamp) {
        System.err.println("Security Error: Timestamp is in the future.");
      }

      // --- Integrity verification ---
      if (!rootJson.has("signature")) {
        System.err.println("Security Error: Signature missing.");
        return;
      }

      String b64Signature = rootJson.get("signature").getAsString();
      byte[] signatureBytes = Base64.getDecoder().decode(b64Signature);

      JsonObject headerObject = rootJson.get("header").getAsJsonObject();
      StringBuilder sb = new StringBuilder();

      sb.append(headerObject.get("author").getAsString());
      sb.append(headerObject.get("version").getAsString());

      JsonArray tags = headerObject.getAsJsonArray("tags");
      for (int i = 0; i < tags.size(); i++) {
        sb.append(tags.get(i).getAsString());
      }
      sb.append(headerObject.get("title").getAsString());

      sb.append(rootJson.get("body").getAsString());
      sb.append(rootJson.get("status").getAsString());
      sb.append(rootJson.get("timestamp").getAsLong());

      String dataToVerify = sb.toString();

      PublicKey pubKey = readPublicKey(keyPath);

      Signature rsa = Signature.getInstance("SHA256withRSA");
      rsa.initVerify(pubKey);
      rsa.update(dataToVerify.getBytes());

      boolean isSigValid = rsa.verify(signatureBytes);

      if (!isSigValid) {
        System.err.println("Security Error: rootJson has been tampered with.");
        return;
      }

      System.out.println("rootJson is authentic");

      System.out.println("rootJson header:");
      System.out.println("Author: " + headerObject.get("author").getAsString());
      System.out.println("Version: " + headerObject.get("version").getAsInt());
      JsonArray tagsArray = headerObject.getAsJsonArray("tags");
      System.out.print("Tags: ");
      for (int i = 0; i < tagsArray.size(); i++) {
        System.out.print(tagsArray.get(i).getAsString());
        if (i < tagsArray.size() - 1) {
          System.out.print(", ");
        } else {
          System.out.println(); // Print a newline after the final tag
        }
      }
      System.out.println("Title: " + headerObject.get("title").getAsString());

      System.out.println("rootJson body: " + rootJson.get("body").getAsString());

      System.out.println("rootJson status: " + rootJson.get("status").getAsString());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
