package com.rocketchat.hacking.services;

import org.spongycastle.crypto.ExtendedDigest;
import org.apache.commons.codec.binary.Hex;
import org.spongycastle.crypto.PBEParametersGenerator;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA224Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.digests.SHA384Digest;
import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class RCTPbkdf2 {

    public RCTPbkdf2() {
        System.out.println("RCTPBkdf2");
    }

    public String getName() {
        return "RCTPbkdf2";
    }

    public String hash(String pwdBase64, String saltBase64, Integer iterations, Integer keyLen, String hash) {
        byte[] digest=null;
        try {
            byte[] pwdBytes = Base64.getDecoder().decode(pwdBase64);
            byte[] saltBytes = Base64.getDecoder().decode(saltBase64);
            digest = pbkdf2(pwdBytes, saltBytes, iterations, keyLen, hash);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return Hex.encodeHexString(digest);
    }

    private static byte[] pbkdf2(byte[] pwd, byte[] salt, Integer iterations, Integer keyLen, String hash) throws NullPointerException, NoSuchAlgorithmException {
        Map<String, ExtendedDigest> algMap = new HashMap<String, ExtendedDigest>();
        algMap.put("SHA1", new SHA1Digest());
        algMap.put("SHA224", new SHA224Digest());
        algMap.put("SHA256", new SHA256Digest());
        algMap.put("SHA384", new SHA384Digest());
        algMap.put("SHA512", new SHA512Digest());
        ExtendedDigest alg = algMap.get(hash);

        if (alg == null) {
            throw new NoSuchAlgorithmException("Specified hash algorithm is not supported");
        }

        PBEParametersGenerator gen = new PKCS5S2ParametersGenerator(alg);
        gen.init(pwd, salt, iterations);
        return ((KeyParameter) gen.generateDerivedParameters(keyLen * 8)).getKey();
    }
}

