package pt.tecnico;

public class LocalSecureDocs {

  public static void main(String[] args) {
    if (args.length < 1) {
      printUsage();
      return;
    }

    String command = args[0];
    SecureLibrary library = new SecureLibrary();

    try {
      switch (command) {
        case "protect":
          if (args.length < 5) {
            System.out.println("Usage: protect <input> <output> <privKey> <secretKey>");
            return;
          }
          library.protect(args[1], args[2], args[3], args[4]);
          break;

        case "check":
          if (args.length < 4) {
            System.out.println("Usage: check <input> <pubKey> <secretKey> [validitySeconds]");
            return;
          }

          // Default validity
          long validity = SecureLibrary.DEFAULT_FRESHNESS_WINDOW;

          // Parse optional validity argument (in seconds)
          if (args.length >= 5) {
            try {
              long seconds = Long.parseLong(args[4]);
              validity = seconds * 1000;
            } catch (NumberFormatException e) {
              System.err.println("Warning: Invalid validity format. Using default (120s).");
            }
          }

          boolean valid = library.check(args[1], args[2], args[3], validity);
          System.exit(valid ? 0 : 1);
          break;

        case "unprotect":
          if (args.length < 4) {
            System.out.println("Usage: unprotect <input> <output> <secretKey>");
            return;
          }
          library.unprotect(args[1], args[2], args[3]);
          break;

        default:
          System.out.println("Unknown command: " + command);
          printUsage();
      }
    } catch (Exception e) {
      System.err.println("Error executing " + command + ": " + e.getMessage());
      e.printStackTrace();
    }
  }

  private static void printUsage() {
    System.out.println("Usage:");
    System.out.println("  protect   <inputFile> <outputFile> <privateKeyPath> <secretKeyPath>");
    System.out.println("  check     <inputFile> <publicKeyPath> <secretKeyPath> [validitySeconds]");
    System.out.println("  unprotect <inputFile> <outputFile> <secretKeyPath>");
  }
}
