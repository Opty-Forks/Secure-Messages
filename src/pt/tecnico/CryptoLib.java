package pt.tecnico;

import com.google.gson.JsonObject;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.MessageDigest;
import java.util.*;


public class CryptoLib {

    public static final String DIGEST_ALGO = "SHA-256";
    public static final String RSA_ALGO = "RSA/ECB/PKCS1Padding";
    public static final String AES_ALGO = "AES/ECB/PKCS5Padding";
    public static final int SIGNATURE_SIZE = 256;
    public static final int FRESHNESS_MILLIS = 1000;

    public static byte[] doDigest(byte[] data) throws Exception {
        System.out.println("Digesting using " + DIGEST_ALGO + "(...)");
        MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);
        messageDigest.update(data);
        byte[] digestBytes = messageDigest.digest();
        System.out.println("Result: " + digestBytes.length + " Bytes");
        return digestBytes;
    }

    public static byte[] doFinal(byte[] data, Key key, String algo, int mode) throws Exception {
        System.out.println("Ciphering using " + algo + "(...)");
        Cipher cipher = Cipher.getInstance(algo);
        cipher.init(mode, key);
        byte[] cipherBytes = cipher.doFinal(data);
        System.out.println("Result: " + cipherBytes.length + " Bytes");
        return cipherBytes;
    }

    public static byte[] addConfidentialityAndIntegrity(byte[] data, Key privKey, Key secretKey) throws Exception {
        byte[] digest = doDigest(data);
        byte[] signature = doFinal(digest, privKey, RSA_ALGO, Cipher.ENCRYPT_MODE);
        /* Attack Integrity
        ByteBuffer buff = ByteBuffer.allocate(plainBytes.length + signature.length + 8);
        buff.put("Modified".getBytes());
        */
        byte[] messageEncrypted = doFinal(data, secretKey, AES_ALGO, Cipher.ENCRYPT_MODE);
        System.out.println("Encrypted Message: " + Base64.getEncoder().encodeToString(messageEncrypted));
        ByteBuffer dataBuf = ByteBuffer.allocate(messageEncrypted.length + signature.length);
        dataBuf.put(messageEncrypted);
        dataBuf.put(signature);
        return dataBuf.array();
    }

    public static boolean checkConfidentialityAndIntegrity(byte[] dataEncrypted, int dataEncryptedLength, Key pubKey, Key secretKey, ByteBuffer dataBuf) throws Exception {

        ByteBuffer dataEncryptedBuf = ByteBuffer.allocate(dataEncryptedLength);
        dataEncryptedBuf.put(dataEncrypted, 0, dataEncryptedLength);

        byte[] messageEncrypted = new byte[dataEncryptedLength - SIGNATURE_SIZE];
        byte[] signature = new byte[SIGNATURE_SIZE];

        dataEncryptedBuf.position(0);
        dataEncryptedBuf.get(messageEncrypted, 0, dataEncryptedLength - SIGNATURE_SIZE);
        dataEncryptedBuf.get(signature, 0, SIGNATURE_SIZE);

        dataBuf.put(doFinal(messageEncrypted, secretKey, AES_ALGO, Cipher.DECRYPT_MODE));

        byte[] dataTrim = new byte[dataBuf.position()];
        dataBuf.position(0);
        dataBuf.get(dataTrim, 0, dataTrim.length);

        byte[] requestDigest = CryptoLib.doFinal(signature, pubKey, RSA_ALGO, Cipher.DECRYPT_MODE);
        if (Arrays.equals(requestDigest, CryptoLib.doDigest(dataTrim))) {
            System.out.println("Integrity Accepted!");
            return true;
        }
        System.out.println("Integrity Rejected!");
        return false;
    }

    public static Map<String, Long> getFreshness(JsonObject json) {

        JsonObject infoJson = json.getAsJsonObject("info");
        String body = json.get("body").getAsString();
        String from = infoJson.get("from").getAsString();
        String to = infoJson.get("to").getAsString();
        Long ts = infoJson.get("ts").getAsLong();
        Long nonce = infoJson.get("nonce").getAsLong();

        System.out.printf("Message: From '%s' To '%s'%n", from, to);
        System.out.printf("Freshness: Nonce '%d' Ts '%d'%n", nonce, ts);
        System.out.printf("Body: '%s'%n", body);

        return new HashMap<String, Long>() {{
            put("ts", ts);
            put("nonce", nonce);
        }};
    }

    public static boolean checkFreshness(Map<Long, Long> freshBuf, Map<String, Long> freshness) {

        if (Math.abs(System.currentTimeMillis() - freshness.get("ts")) > FRESHNESS_MILLIS ||
                freshBuf.containsKey(freshness.get("nonce"))) {
            System.out.println("Freshness Rejected!");
            return false;
        }
        System.out.println("Freshness Accepted!");
        freshBuf.put(freshness.get("nonce"), freshness.get("ts"));
        return true;
    }
}
