package com.example.cloudconfigpropserver.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.example.cloudconfigpropserver.exception.CertificateGenerationException;
import com.example.cloudconfigpropserver.exception.DecryptException;
import com.example.cloudconfigpropserver.exception.EncryptException;

@Service
public class CryptService {

	private static final String CIPHER = "{cipher}";
	private static final String PKCS12 = "PKCS12";

	public String extractAliasFromFile(MultipartFile file, String extension) {
		String filename = Optional.ofNullable(file.getOriginalFilename())
				.orElseThrow(() -> new IllegalArgumentException("Arquivo sem nome"));

		if (!filename.toLowerCase().endsWith(extension)) {
			throw new IllegalArgumentException("Arquivo deve ter extensão " + extension);
		}

		return filename.substring(0, filename.lastIndexOf('.'));
	}

	public String encrypt(MultipartFile certificateFile, String certificatePassword, String aliasName, String data)
			throws CertificateGenerationException {
		try {
			var keystore = KeyStore.getInstance(PKCS12);

			try (var fis = certificateFile.getInputStream()) {
				keystore.load(fis, certificatePassword.toCharArray());
			}

			var privateKey = (PrivateKey) keystore.getKey(aliasName, certificatePassword.toCharArray());

			var cert = keystore.getCertificate(aliasName);

			var keyPair = new KeyPair(cert.getPublicKey(), privateKey);

			var encryptor = new RsaSecretEncryptor(keyPair);

			return CIPHER + encryptor.encrypt(data);
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
				| IOException e) {
			throw new EncryptException("Erro ao criptografar a informação", e);
		}
	}

	public String encryptWithPem(MultipartFile pemFile, String data) throws CertificateGenerationException {
		try {
			String pem = new String(pemFile.getBytes(), StandardCharsets.UTF_8);

			String base64 = pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "")
					.replaceAll("\\s", "");

			byte[] keyBytes = Base64.getDecoder().decode(base64);

			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			PublicKey publicKey = keyFactory.generatePublic(keySpec);

			var encryptor = new RsaSecretEncryptor(publicKey);

			return CIPHER + encryptor.encrypt(data);
		} catch (Exception e) {
			throw new EncryptException("Erro ao criptografar a informação com chave pública PEM", e);
		}
	}

	public String decrypt(MultipartFile certificateFile, String certificatePassword, String aliasName,
			String encryptedData) throws CertificateGenerationException {
		try {
			var keystore = KeyStore.getInstance(PKCS12);

			try (var fis = certificateFile.getInputStream()) {
				keystore.load(fis, certificatePassword.toCharArray());
			}

			var privateKey = (PrivateKey) keystore.getKey(aliasName, certificatePassword.toCharArray());

			var cert = keystore.getCertificate(aliasName);

			var keyPair = new KeyPair(cert.getPublicKey(), privateKey);

			var encryptor = new RsaSecretEncryptor(keyPair);

			// remove prefixo {cipher}, se presente
			var dataToDecrypt = encryptedData.startsWith(CIPHER) ? encryptedData.substring(CIPHER.length())
					: encryptedData;

			return encryptor.decrypt(dataToDecrypt);
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
				| IOException e) {
			throw new DecryptException("Erro ao descriptografar a informação", e);
		}
	}
}