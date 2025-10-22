//package main;
//
//import javax.crypto.*;
//import javax.crypto.spec.SecretKeySpec;
//import javax.crypto.spec.IvParameterSpec;
//import java.io.*;
//import java.nio.file.Files;
//import java.nio.file.Paths;
//import java.security.*;
//import java.util.Base64;
//
//public class AuthenticatedCipher {
//    private static final int AES_KEY_SIZE = 256;
//    private static final int IV_SIZE = 16;
//
//    private static byte[] encrypt(byte[] data, byte[] key) throws Exception {
//        byte[] iv = new byte[IV_SIZE];
//        SecureRandom random = new SecureRandom();
//        random.nextBytes(iv);
//
//        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
//        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
//
//        byte[] encrypted = cipher.doFinal(data);
//        byte[] mac = calculateHMAC(encrypted, key);
//
//        ByteArrayOutputStream output = new ByteArrayOutputStream();
//        output.write(iv);
//        output.write(encrypted);
//        output.write(mac);
//
//        return Base64.getEncoder().encode(output.toByteArray());
//    }
//
//    private static byte[] decrypt(byte[] encryptedData, byte[] key) throws Exception {
//        byte[] decoded = Base64.getDecoder().decode(encryptedData);
//        byte[] iv = new byte[IV_SIZE];
//        System.arraycopy(decoded, 0, iv, 0, IV_SIZE);
//
//        int macSize = 32;
//        byte[] mac = new byte[macSize];
//        System.arraycopy(decoded, decoded.length - macSize, mac, 0, macSize);
//
//        byte[] cipherText = new byte[decoded.length - IV_SIZE - macSize];
//        System.arraycopy(decoded, IV_SIZE, cipherText, 0, cipherText.length);
//
//        byte[] calculatedMac = calculateHMAC(cipherText, key);
//        if (!MessageDigest.isEqual(mac, calculatedMac)) {
//            throw new SecurityException("Authentication failed: HMAC validation failed.");
//        }
//
//        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
//        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
//
//        return cipher.doFinal(cipherText);
//    }
//
//    private static byte[] calculateHMAC(byte[] data, byte[] key) throws Exception {
//        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
//        Mac mac = Mac.getInstance("HmacSHA256");
//        mac.init(keySpec);
//        return mac.doFinal(data);
//    }
//
//    public static void generateKey(String key) throws IOException, NoSuchAlgorithmException {
//        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//        keyGenerator.init(AES_KEY_SIZE);
//        SecretKey secretKey = keyGenerator.generateKey();
//        Files.write(Paths.get(key), secretKey.getEncoded());
//        System.out.println("Chave gerada: " + key);
//    }
//
//    public static void main(String[] args) throws Exception {
//        if (args.length < 1) {
//            System.out.println("Uso: java AuthenticatedCipher -genkey | -cipher | -decipher");
//            return;
//        }
//
//        String mode = args[0];
//        String input = "trab1/src/main/java/main/mensagem.txt";
//        String keyFile = "trab1/src/main/java/main/chave.key";
//        String output = "trab1/src/main/java/main/mensagem_decifrada.txt";
//
//        if (mode.equals("-genkey")) {
//            generateKey(keyFile);
//            return;
//        }
//
//        byte[] key = Files.readAllBytes(Paths.get(keyFile));
//
//        if (mode.equals("-cipher")) {
//            byte[] data = Files.readAllBytes(Paths.get(input));
//            byte[] encryptedData = encrypt(data, key);
//            Files.write(Paths.get(output), encryptedData);
//            System.out.println("Ficheiro cifrado guardado: " + output);
//        } else if (mode.equals("-decipher")) {
//            byte[] encryptedData = Files.readAllBytes(Paths.get(output));
//            try {
//                byte[] decryptedData = decrypt(encryptedData, key);
//                Files.write(Paths.get(input), decryptedData);
//                System.out.println("Ficheiro decifrado guardado: " + input);
//            } catch (SecurityException e) {
//                System.out.println("Falha na autenticaçao: " + e.getMessage());
//            }
//        } else {
//            System.out.println("ERRO! Use -genkey, -cipher ou -decipher.");
//        }
//    }
//}
// java
package main;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class AuthenticatedCipher {

    private static final int AES_KEY_SIZE = 256; // bits
    private static final int IV_SIZE = 16;       // bytes
    private static final int MAC_SIZE = 32;      // HMAC-SHA256 bytes

    private static byte[] hmac256(byte[] key, byte[]... parts) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        for (byte[] p : parts) mac.update(p);
        return mac.doFinal();
    }

    private static byte[] encrypt(byte[] plaintext, byte[] key) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        // T_k(E_k(m)) onde E_k(m) ≙ IV||ciphertext (autenticar também o IV)
        byte[] tag = hmac256(key, iv, ciphertext);

        // Formato: Base64( IV || ciphertext || tag )
        byte[] out = new byte[IV_SIZE + ciphertext.length + MAC_SIZE];
        System.arraycopy(iv, 0, out, 0, IV_SIZE);
        System.arraycopy(ciphertext, 0, out, IV_SIZE, ciphertext.length);
        System.arraycopy(tag, 0, out, IV_SIZE + ciphertext.length, MAC_SIZE);
        return Base64.getEncoder().encode(out);
    }

    private static byte[] decrypt(byte[] protectedB64, byte[] key) throws Exception {
        byte[] all = Base64.getDecoder().decode(protectedB64);
        if (all.length < IV_SIZE + MAC_SIZE + 1)
            throw new SecurityException("Formato inválido.");

        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(all, 0, iv, 0, IV_SIZE);

        byte[] tag = new byte[MAC_SIZE];
        System.arraycopy(all, all.length - MAC_SIZE, tag, 0, MAC_SIZE);

        int ctLen = all.length - IV_SIZE - MAC_SIZE;
        byte[] ciphertext = new byte[ctLen];
        System.arraycopy(all, IV_SIZE, ciphertext, 0, ctLen);

        byte[] calc = hmac256(key, iv, ciphertext);
        if (!MessageDigest.isEqual(tag, calc))
            throw new SecurityException("Autenticidade inválida (HMAC falhou).");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }

    public static void generateKey(String keyPath) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_SIZE);
        SecretKey k = kg.generateKey();
        Files.write(Paths.get(keyPath), k.getEncoded());
        System.out.println("Chave gerada em: '" + keyPath + "'");
    }

    private static void encryptFile(String in, String out, String keyFile) throws Exception {
        byte[] key = Files.readAllBytes(Paths.get(keyFile));
        byte[] data = Files.readAllBytes(Paths.get(in));
        byte[] prot = encrypt(data, key);
        Files.write(Paths.get(out), prot);
        System.out.println("Protegido (Base64) em: '" + out + "'");
    }

    private static boolean decryptFile(String in, String out, String keyFile) throws Exception {
        byte[] key = Files.readAllBytes(Paths.get(keyFile));
        byte[] prot = Files.readAllBytes(Paths.get(in));
        try {
            byte[] plain = decrypt(prot, key);
            Files.write(Paths.get(out), plain);
            System.out.println("Autenticidade: válida");
            System.out.println("Desprotegido em: '" + out + "'");
            return true;
        } catch (SecurityException se) {
            System.out.println("Autenticidade: inválida (" + se.getMessage() + ")");
            return false;
        }
    }

    private static void usage() {
        System.out.println("Uso:");
        System.out.println("  -genkey <keyfile>");
        System.out.println("  -cipher <input> <output> <keyfile>");
        System.out.println("  -decipher <input> <output> <keyfile>");
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            usage();
            return;
        }
        String mode = args[0];
        switch (mode) {
            case "-genkey":
                if (args.length != 2) { usage(); return; }
                generateKey(args[1]);
                break;
            case "-cipher":
                if (args.length != 4) { usage(); return; }
                encryptFile(args[1], args[2], args[3]);
                break;
            case "-decipher":
                if (args.length != 4) { usage(); return; }
                decryptFile(args[1], args[2], args[3]);
                break;
            default:
                usage();
        }
    }
}