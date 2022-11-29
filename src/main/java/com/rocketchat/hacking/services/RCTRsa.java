package com.rocketchat.hacking.services;



import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import com.rocketchat.hacking.services.RSA;

public class RCTRsa  {

  public RCTRsa() {
    System.out.println("RCTRSA");
  }

  public String getName() {
    return "RCTRsa";
  }

  private String getAlgorithmFromHash(final String hash) {
    if (hash.equals("Raw")) {
        return "NONEwithRSA";
    } else if (hash.equals("SHA1")) {
        return "SHA1withRSA";
    } else if (hash.equals("SHA224")) {
        return "SHA224withRSA";
    } else if (hash.equals("SHA256")) {
        return "SHA256withRSA";
    } else if (hash.equals("SHA384")) {
        return "SHA384withRSA";
    } else {
        return "SHA1withRSA";
    }
}

  
  /**
 * @param keySize
 * @return
 */
public HashMap<String,Object> generateKeys(final int keySize) {
        HashMap<String, Object> keys = new HashMap<String, Object>();
        try {
          RSA rsa = new RSA();
          rsa.generate(keySize);
          keys.put("public", rsa.getPublicKey());
          keys.put("private", rsa.getPrivateKey());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return keys;
  }

  public String encrypt(final String message, final String publicKeyString) {
    String encodedMessage="";    
    try {
          RSA rsa = new RSA();
          rsa.setPublicKey(publicKeyString);
          encodedMessage = rsa.encrypt(message);

        } catch (Exception e) {
          e.printStackTrace();
        }
    return encodedMessage;
  }


  public String encrypt64(final String message, final String publicKeyString) {
    String encodedMessage=null;
        try {
          RSA rsa = new RSA();
          rsa.setPublicKey(publicKeyString);
          encodedMessage = rsa.encrypt64(message);
          
        } catch (Exception e) {
           e.printStackTrace();
        }
    return encodedMessage;
  }

  public String decrypt(final String encodedMessage, final String privateKeyString) {
    String message=null;
        try {
          RSA rsa = new RSA();
          rsa.setPrivateKey(privateKeyString);
          message = rsa.decrypt(encodedMessage);
          
        } catch (Exception e) {
          e.printStackTrace();
        }
    return message;
  }


  public String decrypt64(final String encodedMessage, final String privateKeyString) {
    String message=null;
        try {
          RSA rsa = new RSA();
          rsa.setPrivateKey(privateKeyString);
          message = rsa.decrypt64(encodedMessage);
        } catch (Exception e) {
          e.printStackTrace();
        }
      
    return message;
  }

  
  public String sign(final String message, final String privateKeyString, final String hash) {
    String signature= null;
        try {
          RSA rsa = new RSA();
          rsa.setPrivateKey(privateKeyString);
          signature = rsa.sign(message, getAlgorithmFromHash(hash));
        } catch (Exception e) {
          e.printStackTrace();
        }
    return signature;
  }


  public String sign64(final String message, final String privateKeyString, final String hash) {
    String signature = null;    
    try {
          RSA rsa = new RSA();
          rsa.setPrivateKey(privateKeyString);
          signature = rsa.sign64(message, getAlgorithmFromHash(hash));
        } catch (Exception e) {
          e.printStackTrace();
        }
    return signature;
  }


  public boolean verify(final String signature, final String message, final String publicKeyString, final String hash) {
    boolean verified = false;
    try {
          RSA rsa = new RSA();
          rsa.setPublicKey(publicKeyString);
          verified = rsa.verify(signature, message, getAlgorithmFromHash(hash));

        } catch (Exception e) {
          e.printStackTrace();
        }
    return verified;
  }


  public boolean verify64(final String signature, final String message, final String publicKeyString, final String hash) {
    boolean verified= false;
        try {
          RSA rsa = new RSA();
          rsa.setPublicKey(publicKeyString);
          verified = rsa.verify64(signature, message, getAlgorithmFromHash(hash));
        } catch (Exception e) {
          e.printStackTrace();
        }
    return verified;
  }
}
