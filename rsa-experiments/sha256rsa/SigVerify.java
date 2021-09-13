import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import java.util.Base64;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.security.Signature;

public class SigVerify {

  public static PublicKey get(String filename)
    throws Exception {
    
    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

    X509EncodedKeySpec spec =
      new X509EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePublic(spec);
  }

  public static void main(String[] args) throws Exception {
    PublicKey pubKey = get("./rsakey_pub.der");
    Cipher decryptCipher = Cipher.getInstance("RSA");
    decryptCipher.init(Cipher.DECRYPT_MODE, pubKey);

    byte[] decodedBytes = Base64.getDecoder().decode(args[0]);
    byte[] decryptedMessageBytes = decryptCipher.doFinal(decodedBytes);
    String base64decrypted = Base64.getEncoder().withoutPadding().encodeToString(decryptedMessageBytes);
    System.out.println(base64decrypted);

    // calculate hash
    // see also https://stackoverflow.com/questions/33305800/difference-between-sha256withrsa-and-sha256-then-rsa/33311324
    String text = "sample input";
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
    String hashBase64 = Base64.getEncoder().withoutPadding().encodeToString(hash);
    System.out.println(hashBase64);

    // verify
    Signature verifySignature = Signature.getInstance("SHA256withRSA");
    verifySignature.initVerify(pubKey);
    verifySignature.update(text.getBytes());
    boolean isVerify = verifySignature.verify(decodedBytes);
    System.out.println("isVerify = " + isVerify);
  }
}

