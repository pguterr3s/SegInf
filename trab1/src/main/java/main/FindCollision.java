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

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String badAppCode = """
                package main;
                
                public class BadApp {
                    private static final String msg = "Hello, I'm the bad app";
                
                    public static void main(String[] args){
                        System.out.println(msg);
                    }
                }
                """;

        String goodAppCode = """
                package main;
                
                public class GoodApp {
                    private static final String msg = "Hello, I'm the good app";
                    private static final String aaaa= "";
                    public static void main(String[] args){
                        System.out.println(msg);
                    }
                }
                """;

        String h16GoodApp = calculateH16(goodAppCode);
        String equivalent = findMessage(badAppCode, h16GoodApp);
        System.out.println("Codigo equivalente encontrado: \n" + equivalent);
    }
}
