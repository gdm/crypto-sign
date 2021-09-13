// see also https://blog.jonm.dev/posts/rsa-public-key-cryptography-in-java/
// from https://www.quickprogrammingtips.com/java/how-to-create-sha256-rsa-signature-using-java.html
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
 
public class SHA256RSA {
     
    public static void main(String[] args) throws Exception {
        String input = "sample input";
         
        // Not a real private key! Replace with your private key!
        final StringBuilder stringBuilder = new StringBuilder(4096);
        Files.lines(Paths.get("./rsakey.pem")).forEach( line -> {
          stringBuilder.append(line);
        } );
        String strPk = stringBuilder.toString();
         
        String base64Signature = signSHA256RSA(input,strPk);
        System.out.println("Signature="+base64Signature);
    }
 
    // Create base64 encoded signature using SHA256/RSA.
    private static String signSHA256RSA(String input, String strPk) throws Exception {
        // Remove markers and new line characters in private key
        String realPK = strPk.replaceAll("-----END PRIVATE KEY-----", "")
                             .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                             .replaceAll("\n", "");
 
        byte[] b1 = Base64.getDecoder().decode(realPK);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(b1);
        KeyFactory kf = KeyFactory.getInstance("RSA");
 
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(kf.generatePrivate(spec));
        privateSignature.update(input.getBytes("UTF-8"));
        byte[] s = privateSignature.sign();
        return Base64.getEncoder().encodeToString(s);
    }
}

