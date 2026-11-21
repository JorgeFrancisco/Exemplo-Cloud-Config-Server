package com.example.cloudconfigpropserver.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.example.cloudconfigpropserver.exception.InvalidFileException;
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

	public List<String> listAliases(MultipartFile pfxFile, String password) {
		try {
			return Collections.list(loadKeyStore(pfxFile, password).aliases());
		} catch (KeyStoreException e) {
			throw new PublicKeyGenerationException("Erro ao listar os aliases do arquivo pfx", e);
		}
	}

	public AppFile exportPublicKeyAsPemToAppFile(PublicKey publicKey, String fileName) {
		var pem = exportPublicKeyAsPem(publicKey);

		return new AppFile(fileName, pem.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Exporta a chave publica do pfx. O alias e lido de dentro do keystore, entao o nome do
	 * arquivo enviado nao importa.
	 */
	public AppFile exportPublicKeyAsPem(MultipartFile pfxFile, String password) {
		try {
			var keyStore = loadKeyStore(pfxFile, password);

			var alias = resolveAlias(keyStore);

			var cert = keyStore.getCertificate(alias);

			if (cert == null) {
				throw new InvalidFileException("O alias '" + alias + "' do arquivo pfx não possui certificado");
			}

			return exportPublicKeyAsPemToAppFile(cert.getPublicKey(), alias + Constants.PEM);
		} catch (KeyStoreException e) {
			throw new PublicKeyGenerationException("Erro ao extrair a chave pública", e);
		}
	}

	private String exportPublicKeyAsPem(PublicKey publicKey) {
		var encoded = publicKey.getEncoded();

		var base64 = Base64.getEncoder().encodeToString(encoded);

		var pem = new StringBuilder();

		pem.append(Constants.BEGIN_PUBLIC_KEY).append("\n").append(base64.replaceAll("(.{64})", "$1\n")).append("\n")
				.append(Constants.END_PUBLIC_KEY).append("\n");

		return pem.toString();
	}

	private KeyStore loadKeyStore(MultipartFile pfxFile, String password) {
		try {
			var keyStore = KeyStore.getInstance(Constants.PKCS12);

			try (InputStream inputStream = pfxFile.getInputStream()) {
				keyStore.load(inputStream, password.toCharArray());
			}

			return keyStore;
		} catch (IOException | CertificateException e) {
			// O PKCS12 informa senha incorreta e arquivo corrompido com a mesma IOException
			throw new InvalidFileException("Arquivo pfx inválido ou senha incorreta", e);
		} catch (KeyStoreException | NoSuchAlgorithmException e) {
			throw new PublicKeyGenerationException("Erro ao abrir o arquivo pfx", e);
		}
	}

	/**
	 * Os pfx gerados pelo endpoint /certificate possuem um unico alias. Se houver mais de um,
	 * nao ha como saber qual usar, entao a requisicao e recusada.
	 */
	private String resolveAlias(KeyStore keyStore) throws KeyStoreException {
		var aliases = Collections.list(keyStore.aliases());

		if (aliases.isEmpty()) {
			throw new InvalidFileException("O arquivo pfx não possui nenhum alias");
		}

		if (aliases.size() > 1) {
			throw new InvalidFileException("O arquivo pfx possui mais de um alias: " + String.join(", ", aliases));
		}

		return aliases.get(0);
	}
}
