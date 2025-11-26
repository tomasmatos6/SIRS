package pt.tecnico;

import java.io.FileReader;
import java.io.FileWriter;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

public class Adversary {
  public static void main(String[] args) {
    if (args.length < 2) {
      System.out.println("Usage: java Adversary <file> <attackType>");
      System.out.println("Attack Types: 'tamper-data', 'tamper-timestamp'");
      return;
    }

    String filename = args[0];
    String attackType = args[1];

    try {
      // Read the original file
      Gson gson = new GsonBuilder().setPrettyPrinting().create();
      JsonObject jsonObject;
      try (FileReader reader = new FileReader(filename)) {
        jsonObject = gson.fromJson(reader, JsonObject.class);
      }

      // Perform the Attack
      switch (attackType) {
        case "tamper-data":
          System.out.println("Adversary: Modifying Author and Body...");
          // Modify Header
          jsonObject.get("header").getAsJsonObject().addProperty("author", "Loki");
          // Modify Body
          jsonObject.addProperty("body", "I have corrupted this file.");
          break;

        case "tamper-timestamp":
          System.out.println("Adversary: Updating timestamp to 'Now' to bypass freshness check...");
          long now = System.currentTimeMillis();
          jsonObject.addProperty("timestamp", now);
          break;

        default:
          System.out.println("Unknown attack type.");
          return;
      }

      // Save the corrupted file
      try (FileWriter writer = new FileWriter(filename)) {
        gson.toJson(jsonObject, writer);
      }
      System.out.println("Adversary: Malicious file saved to " + filename);

    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
