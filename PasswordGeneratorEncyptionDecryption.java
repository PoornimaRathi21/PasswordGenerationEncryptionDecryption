/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Project/Maven2/JavaApp/src/main/java/${packagePath}/${mainClassName}.java to edit this template
 */

package com.mycompany.passwordgeneratorencyptiondecryption;

/**
 *
 * @author DeLL
 */

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class PasswordGeneratorEncyptionDecryption {
    
    private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5PADDING";
    private static final int IV_LENGTH = 16; // AES initialization vector length
    private static final int KEY_LENGTH = 256; // AES key length
    
    public static void main(String[] args) throws Exception {
        // Generate secret key
        SecretKey secretKey = generateSecretKey();
        
        // Generate password
        String password = generatePassword(8, 16);
        System.out.println("Generated Password: " + password);

        // Encrypt password
        String encryptedPassword = encryptPassword(password, secretKey);
        System.out.println("Encrypted Password: " + encryptedPassword);

        // Decrypt password
        String decryptedPassword = decryptPassword(encryptedPassword, secretKey);
        System.out.println("Decrypted Password: " + decryptedPassword);
    }

    public static SecretKey generateSecretKey() throws Exception {
        // Initialize the KeyGenerator with the AES algorithm
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

        // Generate a secure random AES key with the specified key length
        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(KEY_LENGTH, secureRandom);

        // Generate the secret key
        return keyGenerator.generateKey();
    }

    public static String generatePassword(int minLength, int maxLength) {
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder();

        String lower = "abcdefghijklmnopqrstuvwxyz";
        String upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String digits = "0123456789";
        String specialCharacters = "!@#$%^&*()-_+=";
        String allCharacters = lower + upper + digits + specialCharacters;

        // Ensure at least one character from each character set
        password.append(lower.charAt(random.nextInt(lower.length())));
        password.append(upper.charAt(random.nextInt(upper.length())));
        password.append(digits.charAt(random.nextInt(digits.length())));
        password.append(specialCharacters.charAt(random.nextInt(specialCharacters.length())));

        // Fill the rest of the password with random characters
        int remainingLength = random.nextInt(maxLength - minLength + 1) + minLength - 4;
        for (int i = 0; i < remainingLength; i++) {
            password.append(allCharacters.charAt(random.nextInt(allCharacters.length())));
        }

        // Shuffle the password characters
        for (int i = password.length() - 1; i > 0; i--) {
            int index = random.nextInt(i + 1);
            char temp = password.charAt(index);
            password.setCharAt(index, password.charAt(i));
            password.setCharAt(i, temp);
        }

        return password.toString();
    }

    public static String encryptPassword(String password, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        byte[] combinedArray = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combinedArray, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combinedArray, iv.length, encryptedBytes.length);
        return Base64.getEncoder().encodeToString(combinedArray);
    }

    public static String decryptPassword(String encryptedPassword, SecretKey secretKey) throws Exception {
        byte[] combinedArray = Base64.getDecoder().decode(encryptedPassword);
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(combinedArray, 0, iv, 0, iv.length);
        byte[] encryptedBytes = new byte[combinedArray.length - iv.length];
        System.arraycopy(combinedArray, iv.length, encryptedBytes, 0, encryptedBytes.length);
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}

