import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES_GCM_NoPadding_IV {
	private static final String key128 = "aesEncryptionKey"; // valid for 128, 16 Characteres * 8 = 128bits
	private static final String key256 = "aesEncryptionKeyaesEncryptionKey"; // valid for 256, 32 characteres * 8 =
																				// 256bits
	// para generar llave aleatoria
	private SecretKey key;
	private final int KEY_SIZE = 256;// 128,256

	// private static final String key = "12345678901234567890123456789012";
	private static final String initVector128 = "encryptionIntVec";
	private static final String initVector256 = "encryptionIntVecencryptionIntVec"; // Not valid should be 128bits
	private static final int T_LEN_128 = 128;
	private static final int T_LEN_256 = 256;
	
	public static void main(String... args) {

		String originalString128 = "MensajeAEncriptarCon128AESCBCPKCS5Padding";

		System.out.println("128");
		System.out.println("Original String to encrypt - " + originalString128);
		String encryptedString = encrypt128(originalString128);
		System.out.println("Encrypted String - " + encryptedString);
		String decryptedString = decrypt128(encryptedString);
		System.out.println("After decryption - " + decryptedString);
		System.out.println("256");
		String originalString256 = "MensajeAEncriptarCon256AESCBCPKCS5Padding";
		System.out.println("Original String to encrypt - " + originalString256);
		encryptedString = encrypt256(originalString256);
		System.out.println("Encrypted String - " + encryptedString);
		decryptedString = decrypt256(encryptedString);
		System.out.println("After decryption - " + decryptedString);

		System.out.println("---- Sin IV 128 ----");
		System.out.println("Original String to encrypt - " + originalString128);
		encryptedString = encryptWithoutIv128(originalString128);
		System.out.println("Encrypted String - " + encryptedString);
		decryptedString = decryptWithoutIv128(encryptedString);
		System.out.println("After decryption - " + decryptedString);

		System.out.println("---- Sin IV 256 ----");
		System.out.println("Original String to encrypt - " + originalString256);
		encryptedString = encryptWithoutIv256(originalString256);
		System.out.println("Encrypted String - " + encryptedString);
		decryptedString = decryptWithoutIv256(encryptedString);
		System.out.println("After decryption - " + decryptedString);

	}

	public void init() throws Exception {
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(KEY_SIZE);
		key = generator.generateKey();
	}

	public static String encrypt128(String value) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector128.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key128.getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec spec = new GCMParameterSpec(T_LEN_128, iv.getIV());
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, spec);
			byte[] encryptIV = cipher.getIV();
			System.out.println("IV:" + encryptIV.toString());

			byte[] encrypted = cipher.doFinal(value.getBytes());
			return Base64.getEncoder().encodeToString(encrypted);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	public static String decrypt128(String encrypted) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector128.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key128.getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec spec = new GCMParameterSpec(T_LEN_128, iv.getIV());
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, spec);

			byte[] encryptIV = cipher.getIV();
			System.out.println("IV:" + encryptIV.toString());
			encryptIV = cipher.getIV();
			System.out.println("IV:" + encryptIV.toString());

			byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
			return new String(original);
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}

	public static String encrypt256(String value) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector256.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key256.getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec spec = new GCMParameterSpec(T_LEN_128, iv.getIV());
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, spec);
			byte[] encryptIV = cipher.getIV();
			System.out.println("IV:" + encryptIV.toString());

			byte[] encrypted = cipher.doFinal(value.getBytes());
			return Base64.getEncoder().encodeToString(encrypted);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	public static String decrypt256(String encrypted) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector256.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key256.getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec spec = new GCMParameterSpec(T_LEN_128, iv.getIV());
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, spec);

			byte[] encryptIV = cipher.getIV();
			System.out.println("IV:" + encryptIV.toString());
			encryptIV = cipher.getIV();
			System.out.println("IV:" + encryptIV.toString());

			byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
			return new String(original);
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}

	
	public static String encryptWithoutIv128(String value) {
		try {
			SecretKeySpec skeySpec = new SecretKeySpec(key128.getBytes("UTF-8"), "AES");
			IvParameterSpec iv = new IvParameterSpec(key128.getBytes("UTF-8"));
			
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec spec = new GCMParameterSpec(T_LEN_128, iv.getIV());
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, spec);
			byte[] encryptIV = cipher.getIV();
			System.out.println("IV:" + encryptIV.toString());

			byte[] encrypted = cipher.doFinal(value.getBytes());
			return Base64.getEncoder().encodeToString(encrypted);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	public static String decryptWithoutIv128(String encrypted) {
		try {
			SecretKeySpec skeySpec = new SecretKeySpec(key128.getBytes("UTF-8"), "AES");
			IvParameterSpec iv = new IvParameterSpec(key128.getBytes("UTF-8"));
			
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec spec = new GCMParameterSpec(T_LEN_128, iv.getIV());
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, spec);

			byte[] encryptIV = cipher.getIV();
			System.out.println("IV:" + encryptIV.toString());
			encryptIV = cipher.getIV();
			System.out.println("IV:" + encryptIV.toString());

			byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
			return new String(original);
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}

	public static String encryptWithoutIv256(String value) {
		try {
			SecretKeySpec skeySpec = new SecretKeySpec(key256.getBytes("UTF-8"), "AES");
			IvParameterSpec iv = new IvParameterSpec(key256.getBytes("UTF-8"));
			
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec spec = new GCMParameterSpec(T_LEN_128, iv.getIV());
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, spec);
			byte[] encryptIV = cipher.getIV();
			System.out.println("IV:" + encryptIV.toString());

			byte[] encrypted = cipher.doFinal(value.getBytes());
			return Base64.getEncoder().encodeToString(encrypted);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	public static String decryptWithoutIv256(String encrypted) {
		try {
			SecretKeySpec skeySpec = new SecretKeySpec(key256.getBytes("UTF-8"), "AES");
			IvParameterSpec iv = new IvParameterSpec(key256.getBytes("UTF-8"));
			
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec spec = new GCMParameterSpec(T_LEN_128, iv.getIV());
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, spec);

			byte[] encryptIV = cipher.getIV();
			System.out.println("IV:" + encryptIV.toString());
			encryptIV = cipher.getIV();
			System.out.println("IV:" + encryptIV.toString());

			byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
			return new String(original);
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}

}
