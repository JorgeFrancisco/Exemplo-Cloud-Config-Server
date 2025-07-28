package com.example.cloudconfigpropserver.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;

import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.example.cloudconfigpropserver.exception.CertificateGenerationException;
import com.example.cloudconfigpropserver.exception.DecryptException;
import com.example.cloudconfigpropserver.exception.EncryptException;
import com.example.cloudconfigpropserver.exception.PublicKeyGenerationException;
import com.example.cloudconfigpropserver.model.AppFile;
import com.example.cloudconfigpropserver.model.Constants;

@Service
public class PfxService {

	public AppFile createPfxFile(final KeyPair keyPair, final char[] pwChars, final String alias,
			final X509Certificate x509Cert, final String fileName)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		final var keystore = KeyStore.getInstance(Constants.PKCS12);

		keystore.load(null, null);

		keystore.setKeyEntry(alias, keyPair.getPrivate(), pwChars, new X509Certificate[] { x509Cert });

		byte[] outputStream;

		try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
			keystore.store(byteArrayOutputStream, pwChars);

			outputStream = byteArrayOutputStream.toByteArray();
		}

		return new AppFile(fileName, outputStream);
	}

	public String extractAlias(MultipartFile pfxFile) {
		var filename = Optional.ofNullable(pfxFile.getOriginalFilename())
				.orElseThrow(() -> new IllegalArgumentException("Arquivo sem nome"));

		if (!filename.toLowerCase().endsWith(Constants.PFX)) {
			throw new IllegalArgumentException("Arquivo deve ter extensão " + Constants.PFX);
		}

		return filename.substring(0, filename.lastIndexOf('.'));
	}

	public String encrypt(MultipartFile pfxFile, String pfxPassword, String alias, String data)
			throws CertificateGenerationException {
		try {
			var encryptor = getEncryptor(pfxFile, pfxPassword, alias);

			return Constants.CIPHER + encryptor.encrypt(data);
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
				| IOException e) {
			throw new EncryptException("Erro ao criptografar a informação", e);
		}
	}

	public String decrypt(MultipartFile pfxFile, String pfxPassword, String alias, String encryptedData)
			throws CertificateGenerationException {
		try {
			var encryptor = getEncryptor(pfxFile, pfxPassword, alias);

			var dataToDecrypt = removeCipherPrefix(encryptedData);

			return encryptor.decrypt(dataToDecrypt);
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
				| IOException e) {
			throw new DecryptException("Erro ao descriptografar a informação", e);
		}
	}

	public AppFile exportPublicKeyAsPemToAppFile(PublicKey publicKey, String fileName) {
		var pem = exportPublicKeyAsPem(publicKey);

		return new AppFile(fileName, pem.getBytes(StandardCharsets.UTF_8));
	}

	public AppFile exportPublicKeyAsPem(MultipartFile pfxFile, String password, String alias) {
		PublicKey publicKey = extractPublicKey(pfxFile, password, alias);

		var pem = exportPublicKeyAsPem(publicKey);

		return new AppFile(alias + Constants.PEM, pem.getBytes(StandardCharsets.UTF_8));
	}

	private String exportPublicKeyAsPem(PublicKey publicKey) {
		var encoded = publicKey.getEncoded();

		var base64 = Base64.getEncoder().encodeToString(encoded);

		var pem = new StringBuilder();

		pem.append(Constants.BEGIN_PUBLIC_KEY).append("\n").append(base64.replaceAll("(.{64})", "$1\n")).append("\n")
				.append(Constants.END_PUBLIC_KEY).append("\n");

		return pem.toString();
	}

	private PublicKey extractPublicKey(MultipartFile pfxFile, String password, String alias) {
		try {
			var keyStore = KeyStore.getInstance(Constants.PKCS12);

			try (InputStream inputStream = pfxFile.getInputStream()) {
				keyStore.load(inputStream, password.toCharArray());
			}

			if (!keyStore.containsAlias(alias)) {
				throw new IllegalArgumentException("Alias não encontrado: " + alias);
			}

			var cert = keyStore.getCertificate(alias);

			if (cert == null) {
				throw new IllegalArgumentException("Certificado não encontrado para alias: " + alias);
			}

			return cert.getPublicKey();
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new PublicKeyGenerationException("Erro ao extrair a chave pública", e);
		}
	}

	private String removeCipherPrefix(String encryptedData) {
		return encryptedData.startsWith(Constants.CIPHER) ? encryptedData.substring(Constants.CIPHER.length())
				: encryptedData;
	}

	private RsaSecretEncryptor getEncryptor(MultipartFile pfxFile, String pfxPassword, String alias)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableKeyException {
		var keystore = KeyStore.getInstance(Constants.PKCS12);

		try (var fis = pfxFile.getInputStream()) {
			keystore.load(fis, pfxPassword.toCharArray());
		}

		var privateKey = (PrivateKey) keystore.getKey(alias, pfxPassword.toCharArray());

		var cert = keystore.getCertificate(alias);

		var keyPair = new KeyPair(cert.getPublicKey(), privateKey);

		return new RsaSecretEncryptor(keyPair);
	}
}