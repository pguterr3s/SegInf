package main;

import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class FindCollision {
    private static String calculateH16(String code) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(code.getBytes(StandardCharsets.UTF_8));
        return String.format("%02x%02x", hash[0], hash[1]); // Retorna os primeiros 2 bytes
    }

    private static String findMessage(String origMsg, String target) throws NoSuchAlgorithmException {
        String testMsg = origMsg;
        int count = 0;

        while(true) {
            String candidateMsg = testMsg + count;
            String candidateH16 = calculateH16(candidateMsg);
            if(candidateH16.equals(target)) {
                return candidateMsg;
            }
            count++;
        }
    }

    private static String readFile(String filePath) throws FileNotFoundException {
        StringBuilder sb = new StringBuilder();
        try (Scanner scanner = new Scanner(new File(filePath))) {
            while(scanner.hasNextLine()) {
                sb.append(scanner.nextLine()).append("\n");
            }
        }
        return sb.toString();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, FileNotFoundException {
        String badAppCode = readFile("trab1/src/main/java/main/BadApp.java");
        String goodAppCode = readFile("trab1/src/main/java/main/GoodApp.java");


        String h16GoodApp = calculateH16(goodAppCode);
        String equivalent = findMessage(badAppCode, h16GoodApp);
        System.out.println("Codigo equivalente encontrado: \n" + equivalent);
    }
}
