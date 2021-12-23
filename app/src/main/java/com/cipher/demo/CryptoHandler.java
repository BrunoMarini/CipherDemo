package com.cipher.demo;

import android.annotation.SuppressLint;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CryptoHandler {
    private static class Constraints {
        static final String KEYSTORE = "AndroidKeyStore";
        static final String CHARSET_ENCODING = "UTF-8";
        static final String KEY_GENERATOR_ALGORITHM = "AES";

        static class CBC {
            static final int IV_SIZE = 16;
            static final String BLOCK_MODE = "CBC";
            static final String ALIAS = "TEST_DEMO_APP_KEY_ALIAS";
            static final String ENCRYPTION_PADDING = "PKCS7Padding";
            static final String CIPHER_ALGORITHM = "AES/CBC/" + ENCRYPTION_PADDING;
        }
    }

    public static byte[] encryptData(String text) {
        try {
            Cipher cipherEnc = Cipher.getInstance(Constraints.CBC.CIPHER_ALGORITHM);
            cipherEnc.init(Cipher.ENCRYPT_MODE, getCBCKey());
            byte[] tempIv = cipherEnc.getIV();
            byte[] iv = new byte[Constraints.CBC.IV_SIZE];
            System.arraycopy(tempIv, 0, iv, 0, tempIv.length);

            byte[] cipherText = cipherEnc.doFinal(text.getBytes(Constraints.CHARSET_ENCODING));
            byte[] final_data = new byte[cipherText.length + Constraints.CBC.IV_SIZE];

            System.arraycopy(cipherText, 0, final_data, 0, cipherText.length);
            System.arraycopy(iv, 0, final_data, cipherText.length, Constraints.CBC.IV_SIZE);

            return final_data;

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                BadPaddingException | UnsupportedEncodingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] encryptBulkData(List<String> originalTextList) {
        try {
            Cipher cipherEnc = Cipher.getInstance(Constraints.CBC.CIPHER_ALGORITHM);
            cipherEnc.init(Cipher.ENCRYPT_MODE, getCBCKey());
            byte[] tempIv = cipherEnc.getIV();
            byte[] iv = new byte[Constraints.CBC.IV_SIZE];
            System.arraycopy(tempIv, 0, iv, 0, tempIv.length);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            for (String text : originalTextList) {
                byte[] originalText = text.getBytes(Constraints.CHARSET_ENCODING);
                byte[] encryptedData = cipherEnc.update(originalText);
                outputStream.write(encryptedData);
            }

            byte[] encryptedData = cipherEnc.doFinal();
            outputStream.write(encryptedData);

            byte[] final_data = new byte[Constraints.CBC.IV_SIZE];
            System.arraycopy(iv, 0, final_data, 0, Constraints.CBC.IV_SIZE);
            outputStream.write(final_data);

            byte[] totalEncryptedData = outputStream.toByteArray();
            return totalEncryptedData;

        } catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeyException |
                NoSuchPaddingException | IOException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decryptBulkData(byte[] encText) {
        try {
            Cipher cipherDec = Cipher.getInstance(Constraints.CBC.CIPHER_ALGORITHM);
            int cipherTextSize = encText.length - Constraints.CBC.IV_SIZE;

            byte[] cipherText = new byte[cipherTextSize];
            byte[] iv = new byte[Constraints.CBC.IV_SIZE];

            System.arraycopy(encText, 0, cipherText, 0, cipherTextSize);
            System.arraycopy(encText, cipherTextSize, iv, 0, Constraints.CBC.IV_SIZE);

            cipherDec.init(Cipher.DECRYPT_MODE, getCBCKey(), new IvParameterSpec(iv));
            String decrypted = new String(cipherDec.doFinal(cipherText), Constraints.CHARSET_ENCODING);
            return decrypted;

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException |
                BadPaddingException | IllegalBlockSizeException |
                InvalidAlgorithmParameterException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decryptData(byte[] encText) {
        try {
            Cipher cipherDec = Cipher.getInstance(Constraints.CBC.CIPHER_ALGORITHM);
            int cipherTextSize = encText.length - Constraints.CBC.IV_SIZE;

            byte[] cipherText = new byte[cipherTextSize];
            byte[] iv = new byte[Constraints.CBC.IV_SIZE];

            System.arraycopy(encText, 0, cipherText, 0, cipherTextSize);
            System.arraycopy(encText, cipherTextSize, iv, 0, Constraints.CBC.IV_SIZE);

            cipherDec.init(Cipher.DECRYPT_MODE, getCBCKey(), new IvParameterSpec(iv));
            String decrypted = new String(cipherDec.doFinal(cipherText), Constraints.CHARSET_ENCODING);
            return decrypted;

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException |
                BadPaddingException | IllegalBlockSizeException |
                InvalidAlgorithmParameterException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static SecretKey getCBCKey() {
        KeyStore.SecretKeyEntry secretKeyEntry;
        KeyStore ks = getKeyStore();
        if (ks == null) return null;

        try {
            if (!ks.containsAlias(Constraints.CBC.ALIAS)) {
                return null;
            }
            secretKeyEntry = (KeyStore.SecretKeyEntry) ks.getEntry(Constraints.CBC.ALIAS, null);
            if (secretKeyEntry == null) {
                return null;
            }
            return secretKeyEntry.getSecretKey();
        } catch (KeyStoreException | UnrecoverableEntryException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static KeyStore getKeyStore() {
        try {
            KeyStore ks =KeyStore.getInstance(Constraints.KEYSTORE);
            ks.load(null);
            return ks;
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void generateSecretKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(Constraints.KEY_GENERATOR_ALGORITHM);
            keyGenerator.init(new SecureRandom());
            SecretKey secretKey = keyGenerator.generateKey();
            KeyStore keyStore = getKeyStore();
            @SuppressLint("WrongConstant")
            KeyProtection.Builder builder =
                    new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(Constraints.CBC.BLOCK_MODE)
                            .setEncryptionPaddings(Constraints.CBC.ENCRYPTION_PADDING);

            keyStore.setEntry(Constraints.CBC.ALIAS, new KeyStore.SecretKeyEntry(secretKey), builder.build());

        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            e.printStackTrace();
        }
    }
}
