import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Encryption {

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    // If needed to display encrypted bytes
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            // Get the high nibble and convert it to a hexadecimal character
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            // Get the low nibble and convert it to a hexadecimal character
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static SecretKey getSecretKey(String key) {
        byte[] keyBytes = Arrays.copyOf(key.getBytes(), 16);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        return secretKey;
    }

    public static byte[] encrypt(String message, String key) {
        try {
            SecretKey secretKey = getSecretKey(key);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());
            return encryptedBytes;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(byte[] encryptedBytes, String key) {
        try {
            SecretKey secretKey = getSecretKey(key);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }
}