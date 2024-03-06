import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;


// TODO: fix AES not working
// TODO: create iv creation method
// TODO: create encryption method

// ## UNSTABLE BUILD, AES NOT WORKING ##

public class Encryption {
    public static final Random RANDOM = new SecureRandom();
    /**
     * Return random salt to hash password
     * @return 16 byte random salt
     */
    public static byte[] getNextSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }

    public static byte[] hash(char[] password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 10000, 256);
        Arrays.fill(password, Character.MIN_VALUE);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("AES");
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new AssertionError("Error: " + e.getMessage());
        } finally {
            spec.clearPassword();
        }
    }

    public static void main(String[] args) {
        String password = "test";
        char[] passwordArray = password.toCharArray();

        byte[] salt = getNextSalt();
        byte[] hashed = hash(passwordArray, salt);

        System.out.println("Password: " + password);
        for (byte b : salt) {
            System.out.print(b);
        }
        System.out.println();

        for (byte b : hashed) {
            System.out.print(b);
        }
    }
}