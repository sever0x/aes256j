package com.sever0x.aes256j;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESUtils {

    private AESUtils() {
    }

    private static final String ALGORITHM = "AES";

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private static final int IV_LENGTH = 12; // length for GCM

    private static final int TAG_LENGTH = 16; // tag auth length in GCM

    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(256);
        return keyGen.generateKey();
    }

    public static String encrypt(String text, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        byte[] iv = generateIv();

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH * 8, iv); // TAG_LENGTH in bytes

        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(text.getBytes());
        byte[] encryptedIvAndText = new byte[IV_LENGTH + encryptedBytes.length];

        System.arraycopy(iv, 0, encryptedIvAndText, 0, IV_LENGTH);
        System.arraycopy(encryptedBytes, 0, encryptedIvAndText, IV_LENGTH, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(encryptedIvAndText);
    }

    public static String decrypt(String encryptedText, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedIvAndText = Base64.getDecoder().decode(encryptedText);
        byte[] iv = new byte[IV_LENGTH];
        byte[] encryptedBytes = new byte[encryptedIvAndText.length - IV_LENGTH];

        System.arraycopy(encryptedIvAndText, 0, iv, 0, IV_LENGTH);
        System.arraycopy(encryptedIvAndText, IV_LENGTH, encryptedBytes, 0, encryptedBytes.length);

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH * 8, iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    private static byte[] generateIv() {
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }
}
