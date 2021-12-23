package com.cipher.demo;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.annotation.SuppressLint;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Log;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = MainActivity.class.getSimpleName();

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        CryptoHandler.generateSecretKey();

        String originalText, decryptedText;
        byte[] encryptedText;

        originalText = "Test Cryptography - Bruno Guilherme S. Marini";
        Log.d(TAG, "Original Text: " + originalText);
        encryptedText = CryptoHandler.encryptData(originalText);
        Log.d(TAG, "Encrypted Text: " + new String(encryptedText));
        decryptedText = CryptoHandler.decryptData(encryptedText);
        Log.d(TAG, "Decrypted Text: " + decryptedText);

        List<String> originalTextList = getTestArrayList();
        Log.d(TAG, "Original Text: " + originalTextList);
        encryptedText = CryptoHandler.encryptBulkData(originalTextList);
        Log.d(TAG, "Encrypted Text: " + new String(encryptedText));
        decryptedText = CryptoHandler.decryptBulkData(encryptedText);
        Log.d(TAG, "Decrypted Text: " + decryptedText);
    }

    private List<String> getTestArrayList() {
        return Arrays.asList(
                "abcdefghijklmnopqrstuvwxyz ",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ ",
                "012345678901234567890123456789");
    }
}