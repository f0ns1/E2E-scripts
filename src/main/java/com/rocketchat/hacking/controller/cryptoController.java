package com.rocketchat.hacking.controller;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

import org.apache.commons.codec.binary.Hex;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.rocketchat.hacking.beans.AESBean;
import com.rocketchat.hacking.beans.PBKDf2Bean;
import com.rocketchat.hacking.beans.PrivateKeyBean;
import com.rocketchat.hacking.beans.RSABean;
import com.rocketchat.hacking.services.RCTAes;
import com.rocketchat.hacking.services.RCTPbkdf2;
import com.rocketchat.hacking.services.RCTRSAUtils;
import com.rocketchat.hacking.services.RCTRsa;

@RestController
public class cryptoController {
	private static final String CONTEXT = "/api/v1";
	private static final String AES_DECRYPT = CONTEXT + "/aes-decrypt-message";
	private static final String RSA_GENERATE_KEYS = CONTEXT + "/rsa-generate-keys";
	private static final String RSA_DECRYPT = CONTEXT + "/rsa-decrypt-e2ekey";
	private static final String PBKDF2 = CONTEXT + "/pbkdf2-master-key";
	private static final String DECRYPT_PRIVATE_KEY = CONTEXT + "/decrypt-private-key";

	@RequestMapping(method = RequestMethod.POST, value = AES_DECRYPT)
	public String AESDecrypt(@RequestBody AESBean bean) {
		String output = "";
		try {
			String ciphertext = bean.getCipherText();
			// ciphertext="X/o1IvAYHJPkVggJ3nnkk7ot03N97VBIdyD9tfGGZfi3QtoTelRS8y9VEQnJwdf0mwO8fGj9v/tFT1R/X1kPCEIfh7MnfacsUtNDztbIEAJhCIWZrpXxxTkJSCqVZrk12ZDQmQxk5B6YIbuWcREPlA==";
			String hexKey = bean.getHexKey();
			// hexKey="5c8db182c7f3edf9575c3a181acbbbbc";
			String hexIv = bean.getHexIv();
			// hexIv="2bd319ff7d7463298dc12f0e38a5bc6a";
			output = RCTAes.decrypt(ciphertext, hexKey, hexIv);
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("AESdecrypt: " + output);
		return new String(Base64.getDecoder().decode(output));
	}

	public byte[] encode(String data) {

		return data.getBytes(StandardCharsets.UTF_8);
	}

	@RequestMapping(method = RequestMethod.POST, value = RSA_GENERATE_KEYS)
	public String RSAgenerateKeys(@RequestBody RSABean bean) {
		RCTRsa rsa = new RCTRsa();
		HashMap<String, Object> output = null;
		try {
			int keys = 2048;
			output = rsa.generateKeys(keys);
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("RSAgenerateKeys: " + output);
		RCTRSAUtils utils = new RCTRSAUtils();
		JSONObject public_key = utils.exportKey((String) output.get("public"));
		String data = "{\"alg\":\"RSA-OAEP-256\",\"e\":\"" + public_key.get("e")
				+ "\",\"ext\":true,\"key_ops\":[\"encrypt\"],\"kty\":\"RSA\"";
		data += ",\"n\":" + "\"" + public_key.get("n") + "\"}";
		System.out.println("Public key : " + data);
		JSONArray json = new JSONArray();
		JSONObject private_key = new JSONObject();
		JSONObject pub = new JSONObject();
		pub.put("public_key", data);
		private_key.put("$binary", (String) output.get("private"));
		json.put(pub);
		json.put(private_key);
		System.out.println("jsonData: " + json.toString());
		JSONObject body = new JSONObject();
		body.put("msg", "method");
		body.put("id", "40");
		body.put("method", "e2e.setUserPublicAndPrivateKeys");
		body.put("params", json);
		JSONObject message = new JSONObject();
		message.put("message", body.toString());
		System.out.println("Final message : " + message.toString());
		return message.toString();

	}

	@RequestMapping(method = RequestMethod.POST, value = RSA_DECRYPT)
	public String RSAdecrypt(@RequestBody RSABean bean) {
		RCTRsa rsa = new RCTRsa();
		String output = null;
		try {
			String message = bean.getMessage();
			String privateKey = new String(Base64.getDecoder().decode(bean.getPrivateKey()));
			output = rsa.decrypt(message, privateKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
		JSONObject obj = new JSONObject(output);
		String val = obj.getString("k");
		System.out.println("K value : " + val);
		System.out.println("bytearray: " + Base64.getUrlDecoder().decode(val));
		System.out.println("RSA_decrypt: " + Hex.encodeHexString(Base64.getUrlDecoder().decode(val)));
		return Hex.encodeHexString(Base64.getUrlDecoder().decode(val));
	}

	@RequestMapping(method = RequestMethod.POST, value = PBKDF2)
	public String pbkdf2(@RequestBody PBKDf2Bean bean) {
		RCTPbkdf2 pbkdf2 = new RCTPbkdf2();
		String output = null;
		// Your password is: user earth input virus bishop
		int iterations = 1000;
		String hash = "SHA256";
		int keyLength = 32;
		byte[] passwordBuffer = encode(bean.getPassword());
		byte[] saltUser = encode(bean.getUserId());
		try {

			String master_key = pbkdf2.hash(Base64.getEncoder().encodeToString(passwordBuffer),
					Base64.getEncoder().encodeToString(saltUser), iterations, keyLength, hash);
			System.out.println("getPrivate() encrypted PBKDF2 master-key " + master_key);
			output = master_key;
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("Pbkdf2: " + output);
		return output;
	}

	@RequestMapping(method = RequestMethod.POST, value = DECRYPT_PRIVATE_KEY)
	public PrivateKeyBean decryptPrivateKey(@RequestBody PrivateKeyBean bean) {
		String private_key = bean.getPrivate_key();
		byte[] decode = Base64.getDecoder().decode(private_key);
		byte[] result = Arrays.copyOf(decode, 16);
		String iv = Hex.encodeHexString(result);
		System.out.println("Hex : " + iv);
		byte[] encoded_cipher = Arrays.copyOfRange(decode, 16, decode.length);
		System.out.println(Base64.getEncoder().encodeToString(encoded_cipher));
		String key_cipher = Base64.getEncoder().encodeToString(encoded_cipher);
		try {
			String decrypted = RCTAes.decrypt(key_cipher, bean.getMaster_key(), iv);
			System.out.println("decrypted : " + decrypted);
			System.out.println(new String(Base64.getDecoder().decode(decrypted)));
			String private_string = new String(Base64.getDecoder().decode(decrypted));
			JSONObject privateJson = new JSONObject(private_string);
			RCTRSAUtils utils = new RCTRSAUtils();
			String pem = utils.importKey(privateJson);
			JSONObject output = new JSONObject();
			output.put("private_key", Base64.getEncoder().encodeToString(pem.getBytes()));
			System.out.println("Private key : " + output);
			System.out.println("Private key : " + output.toString());
			bean.setPem_return(output.toString());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return bean;
	}
}
