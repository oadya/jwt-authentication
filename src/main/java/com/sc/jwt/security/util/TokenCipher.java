package com.sc.jwt.security.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class TokenCipher {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(TokenCipher.class);
    private  int keySize = 128;
    private  int iterationCount =1000;
    
    private static final String UNIQUE_KEY = "1234567891234567";
    /**Secure random generator */
    private final SecureRandom secRandom = new SecureRandom();
    
    private static final int GCM_NONCE_LENGTH = 16; // in bytes
    
	public String encodeJwt_Token(String token, String secretkey,byte[] iv ) {
		
	SecretKey key = null;
	Cipher cipher = null;
	String result = null;
      
		try {
		    
//			final byte[] iv = new byte[GCM_NONCE_LENGTH];
//		    secRandom.nextBytes(iv);
		       
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] secretkeyDigest = digest.digest(secretkey.getBytes());
			String secretkeytHash = Base64.encodeBase64String(secretkeyDigest);
			
		    key = generateKey(secretkeytHash);
		     
		    // //Setup Cipher 
		    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");    			
//		    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(hex("59d1d1ad4fbfdcd13913b75ab9391e9a")));
		    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

		    byte[] text = token.getBytes();			    
		    
		    byte[] textEncrypted = cipher.doFinal(text);
		    result =  new String(java.util.Base64.getEncoder().encode(textEncrypted));
		    
		} catch (Exception e) {
			LOGGER.error("Erreur lors du cryptage : ", e);
		}   
    
	  return result;		
    }
	
	public String decodeJwt_Token (String  encryptedParam,String secretkey ) {
		
	SecretKey key = null;
	String result = null;

	    try {
		 
	    //Decodage hexa du token
	    byte[] decodedBytes =  java.util.Base64.getDecoder().decode(encryptedParam);

		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] secretkeyDigest = digest.digest(secretkey.getBytes());
	    String secretkeytHash = Base64.encodeBase64String(secretkeyDigest);	
	     
	     key = generateKey(secretkeytHash);
	     
		 Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		 cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(hex("59d1d1ad4fbfdcd13913b75ab9391e9a")));
		 byte[] textDecrypted = cipher.doFinal(decodedBytes);
		  
		  result = new String(textDecrypted);
		   
		  return result;
	
		} catch (Exception e) {
			LOGGER.error("Erreur lors du decryptage : ", e);
		}  
    return result;	  	
  }
	
    private SecretKey generateKey(String passphrase) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(passphrase.toCharArray(),UNIQUE_KEY.getBytes(), iterationCount, keySize);
            SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
            return key;
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return null;
        }
    }
    
    public static byte[] hex(String str) {
        try {
            return Hex.decodeHex(str.toCharArray());
        }
        catch (DecoderException e) {
            throw new IllegalStateException(e);
        }
    }
    
    public static byte[] base64(String str) {
        return Base64.decodeBase64(str);
    }

}
