package main;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class AuthenticatedCipher {
    private static final int AES_KEY_SIZE = 256;
    private static final int IV_SIZE = 16;

    private static byte[] encrypt(byte[] data, byte[] key) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));

        byte[] encrypted = cipher.doFinal(data);
        byte[] mac = calculateHMAC(encrypted, key);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(iv);
        output.write(encrypted);
        output.write(mac);

        return Base64.getEncoder().encode(output.toByteArray());
    }

    private static byte[] decrypt(byte[] encryptedData, byte[] key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(decoded, 0, iv, 0, IV_SIZE);

        int macSize = 32;
        byte[] mac = new byte[macSize];
        System.arraycopy(decoded, decoded.length - macSize, mac, 0, macSize);

        byte[] cipherText = new byte[decoded.length - IV_SIZE - macSize];
        System.arraycopy(decoded, decoded.length - macSize, cipherText, 0, cipherText.length);

        byte[] calculatedMac = calculateHMAC(cipherText, key);
        if(!MessageDigest.isEqual(mac, calculatedMac)) {
            return null;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

        return cipher.doFinal(cipherText);
    }

    private static byte[] calculateHMAC(byte[] data, byte[] key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    public static void generateKey(String key) throws IOException, NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_KEY_SIZE);
        SecretKey secretKey = keyGenerator.generateKey();
        Files.write(Paths.get(key), secretKey.getEncoded());
        System.out.println("Chave gerada: " + key);
    }

    public static void main(String[] args) throws Exception {
        if(args.length < 4) {
            System.out.println("Uso : java AuthenticatedCipher -cipher|-decipher <arquivo> <chave> <saida>");
            return;
        }
        String mode = args[0];
        String input = args[1];
        String keyFile = args[2];
        String output = args[3];

        byte[] key = Files.readAllBytes(Paths.get(keyFile));

        if(mode.equals("-cipher")) {
            byte[] data = Files.readAllBytes(Paths.get(input));
            byte[] encryptedData = encrypt(data, key);
            Files.write(Paths.get(output), encryptedData);
            System.out.println("Arquivo cifrado guardado: " + output);
        } else if(mode.equals("-decipher")) {
            byte[] encryptedData = Files.readAllBytes(Paths.get(input));
            byte[] decryptedData = decrypt(encryptedData, key);
            if(decryptedData == null) {
                System.out.println("Falha na autenticação.");
                return;
            }
            Files.write(Paths.get(output), decryptedData);
            System.out.println("Arquivo decifrado guardado: " + output);
        } else {
            System.out.println("ERRO! Use -cipher ou -decipher.");
        }
    }
}
