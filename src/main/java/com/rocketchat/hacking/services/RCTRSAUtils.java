package com.rocketchat.hacking.services;


import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemReader;
import org.spongycastle.util.io.pem.PemWriter;



import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.json.JSONObject;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Primitive;

public class RCTRSAUtils  {

  public RCTRSAUtils() {
    System.out.println("Constructor RCTRSAUtils !");
  }


  public String getName() {
    return "RCTRsaUtils";
  }


  public String importKey(JSONObject jwk) {
    String pkcs1=null;
    Boolean isPrivate = (jwk.get("d") != null && jwk.get("d") != "");
    try {
      if (isPrivate) {
        pkcs1 = jwkToPrivatePkcs1(jwk);
      } else {
        pkcs1 = jwkToPublicPkcs1(jwk);
      }

    
    } catch (Exception ex) {
      ex.printStackTrace();
    }
    return pkcs1;
  }


  public JSONObject exportKey(String pem) {
    JSONObject jwk =null;
    try {
      byte[] pkcs1PrivateKey = pemToData(pem);
      ASN1InputStream in = new ASN1InputStream(pkcs1PrivateKey);
      ASN1Primitive obj = in.readObject();
      Boolean isPublic = pem.contains("PUBLIC");

      jwk = isPublic ? pkcs1ToPublicKey(obj) : pkcs1ToPrivateKey(obj);
      jwk.put("kty", "RSA");
      jwk.put("alg", "RSA-OAEP-256");
      jwk.put("ext", true);

      String keyOps=null;
      if (isPublic) {
        keyOps = "encrypt";
      } else {
        keyOps = "decrypt";
      }
      jwk.put("key_ops", "["+keyOps+"]");
      
      
    } catch (Exception e) {
      e.printStackTrace();
    }
    return jwk;
  }

  private String jwkToPublicPkcs1(JSONObject jwk) throws Exception {
    BigInteger modulus = toBigInteger(decodeSequence(jwk.get("n").toString()));
    BigInteger publicExponent = toBigInteger(decodeSequence(jwk.get("e").toString()));

    KeyFactory factory = KeyFactory.getInstance("RSA");
    PublicKey key = factory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

    PemObject pemObject = new PemObject("RSA PUBLIC KEY", publicKeyToPkcs1(key));
    StringWriter stringWriter = new StringWriter();
    PemWriter pemWriter = new PemWriter(stringWriter);
    pemWriter.writeObject(pemObject);
    pemWriter.close();

    return stringWriter.toString();
  }

  public String jwkToPrivatePkcs1(JSONObject jwk) throws Exception {
    BigInteger modulus = toBigInteger(decodeSequence((String)jwk.get("n")));
    BigInteger publicExponent = toBigInteger(decodeSequence(jwk.get("e").toString()));
    BigInteger privateExponent = toBigInteger(decodeSequence(jwk.get("d").toString()));
    BigInteger primeP = toBigInteger(decodeSequence(jwk.get("p").toString()));
    BigInteger primeQ = toBigInteger(decodeSequence(jwk.get("q").toString()));
    BigInteger primeExpP = toBigInteger(decodeSequence(jwk.get("dp").toString()));
    BigInteger primeExpQ = toBigInteger(decodeSequence(jwk.get("dq").toString()));
    BigInteger crtCoefficient = toBigInteger(decodeSequence(jwk.get("qi").toString()));

    KeyFactory factory = KeyFactory.getInstance("RSA");
    RSAPrivateKey key = (RSAPrivateKey) factory.generatePrivate(new RSAPrivateCrtKeySpec(
            modulus,
            publicExponent,
            privateExponent,
            primeP,
            primeQ,
            primeExpP,
            primeExpQ,
            crtCoefficient
    ));

    PemObject pemObject = new PemObject("RSA PRIVATE KEY", privateKeyToPkcs1(key));
    StringWriter stringWriter = new StringWriter();
    PemWriter pemWriter = new PemWriter(stringWriter);
    pemWriter.writeObject(pemObject);
    pemWriter.close();

    return stringWriter.toString();
  }

  private JSONObject pkcs1ToPublicKey(ASN1Primitive obj) {
    org.spongycastle.asn1.pkcs.RSAPublicKey keyStruct = org.spongycastle.asn1.pkcs.RSAPublicKey.getInstance(obj);

    JSONObject jwk = new JSONObject();
    jwk.put("n", toString(keyStruct.getModulus(), true));
    jwk.put("e", toString(keyStruct.getPublicExponent(), false));

    return jwk;
  }

  private JSONObject pkcs1ToPrivateKey(ASN1Primitive obj) {
    org.spongycastle.asn1.pkcs.RSAPrivateKey keyStruct = org.spongycastle.asn1.pkcs.RSAPrivateKey.getInstance(obj);

    JSONObject jwk = new JSONObject();
    jwk.put("n", toString(keyStruct.getModulus(), true));
    jwk.put("e", toString(keyStruct.getPublicExponent(), false));
    jwk.put("d", toString(keyStruct.getPrivateExponent(), false));
    jwk.put("p", toString(keyStruct.getPrime1(), true));
    jwk.put("q", toString(keyStruct.getPrime2(), true));
    jwk.put("dp", toString(keyStruct.getExponent1(), true));
    jwk.put("dq", toString(keyStruct.getExponent2(), true));
    jwk.put("qi", toString(keyStruct.getCoefficient(), false));

    return jwk;
  }

  private byte[] publicKeyToPkcs1(PublicKey publicKey) throws IOException {
    SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    ASN1Primitive primitive = spkInfo.parsePublicKey();
    return primitive.getEncoded();
  }

  private static byte[] privateKeyToPkcs1(PrivateKey privateKey) throws IOException {
    PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
    ASN1Encodable encodeable = pkInfo.parsePrivateKey();
    ASN1Primitive primitive = encodeable.toASN1Primitive();
    return primitive.getEncoded();
  }

  private String toString(BigInteger bigInteger, Boolean positive) {
    byte[] array = bigInteger.toByteArray();
    if (positive) {
      array = Arrays.copyOfRange(array, 1, array.length);
    }
    return Base64.getUrlEncoder().withoutPadding().encodeToString(array);
  }

  private byte[] pemToData(String pemKey) throws IOException {
    Reader keyReader = new StringReader(pemKey);
    PemReader pemReader = new PemReader(keyReader);
    PemObject pemObject = pemReader.readPemObject();
    return pemObject.getContent();
  }

  private static BigInteger toBigInteger(byte[] bytes) {
    return new BigInteger(1, bytes);
  }

  public static byte[] decodeSequence(String encodedSequence) {
    return Base64.getUrlDecoder().decode(encodedSequence);
  }
}
