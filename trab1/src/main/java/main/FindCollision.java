package main;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class FindCollision {



    private static String calculateH16(String code) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(code.getBytes(StandardCharsets.UTF_8));
        return String.format("%02x%02x", hash[0], hash[1]); // Retorna os primeiros 2 bytes
    }
}
