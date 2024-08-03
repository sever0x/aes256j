package com.sever0x.aes256j;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Scanner;

@Component
public class ConsoleRunner implements CommandLineRunner {
    @Override
    public void run(String... args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        SecretKey key = AESUtils.generateSecretKey();
        System.out.println("Enter text for encrypt:");
        String inputText = scanner.nextLine();

        String encryptedText = AESUtils.encrypt(inputText, key);
        System.out.println("Encrypted text: " + encryptedText);

        String decryptedText = AESUtils.decrypt(encryptedText, key);
        System.out.println("Decrypted text: " + decryptedText);
    }
}
