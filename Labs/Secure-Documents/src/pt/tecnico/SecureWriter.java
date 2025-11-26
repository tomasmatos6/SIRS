package pt.tecnico;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class SecureWriter {

  public static PrivateKey readPrivateKey(String keyPath) throws Exception {
    byte[] keyBytes = Files.readAllBytes(new File(keyPath).toPath());
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePrivate(spec);
  }

  public static void main(String[] args) throws IOException {
    // Check arguments
    if (args.length < 2) {
      System.err.println("Argument(s) missing!");
      System.err.printf("Usage: java %s <outputFile> <privateKeyPath>%n",
          SecureWriter.class.getName());
      return;
    }
    final String filename = args[0];
    final String keyPath = args[1];
    final String secretKeyPath = args[2] != null ? args[2] : "../../../keys/secret.key";

    try {
      // Create bank statement JSON object
      JsonObject jsonObject = new JsonObject();

      JsonObject headerObject = new JsonObject();
      headerObject.addProperty("author", "Ultron");
      headerObject.addProperty("version", 2);
      JsonArray tagsArray = new JsonArray();
      tagsArray.add("robot");
      tagsArray.add("autonomy");
      headerObject.add("tags", tagsArray);
      headerObject.addProperty("title", "Avengers 2");
      jsonObject.add("header", headerObject);

      jsonObject.addProperty("body", "I had strings but now I'm free");
      jsonObject.addProperty("status", "published");

      // Write JSON object to file

      // Timestamp to ensure freshness
      long now = System.currentTimeMillis();
      jsonObject.addProperty("timestamp", now);

      // Signature with private key to ensure Integrity and Non-Repudiation
      StringBuilder sb = new StringBuilder();

      sb.append(headerObject.get("author").getAsString());
      sb.append(headerObject.get("version").getAsString());

      JsonArray tags = headerObject.getAsJsonArray("tags");
      for (int i = 0; i < tags.size(); i++) {
        sb.append(tags.get(i).getAsString());
      }
      sb.append(headerObject.get("title").getAsString());

      sb.append(jsonObject.get("body").getAsString());
      sb.append(jsonObject.get("status").getAsString());
      sb.append(jsonObject.get("timestamp").getAsLong());

      String dataToSign = sb.toString();

      PrivateKey privKey = readPrivateKey(keyPath);
      Signature rsa = Signature.getInstance("SHA256withRSA");
      rsa.initSign(privKey);
      rsa.update(dataToSign.getBytes());
      byte[] signatureBytes = rsa.sign();

      String b64Signature = Base64.getEncoder().encodeToString(signatureBytes);
      jsonObject.addProperty("signature", b64Signature);

      String jsonString = new Gson().toJson(jsonObject);
      SecretKeySpec secretKey = CryptoUtils.readSecretKey(secretKeyPath);

      byte[] encryptedBytes = CryptoUtils.encrypt(secretKey, jsonString.getBytes());

      JsonObject document = new JsonObject();
      document.addProperty("secureJson", Base64.getEncoder().encodeToString(encryptedBytes));

      try (FileWriter fileWriter = new FileWriter(filename)) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        gson.toJson(document, fileWriter);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
