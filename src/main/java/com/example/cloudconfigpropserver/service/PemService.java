package com.example.cloudconfigpropserver.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.example.cloudconfigpropserver.exception.EncryptException;
import com.example.cloudconfigpropserver.exception.InvalidFileException;
import com.example.cloudconfigpropserver.model.Constants;

@Service
public class PemService {

	/**
	 * Criptografa usando somente a chave publica. A chave privada continua apenas com a
	 * aplicacao client, que e quem descriptografa.
	 */
	public String encrypt(MultipartFile pemFile, String data) {
		var publicKey = readPublicKey(pemFile);

		try {
			var encryptor = new RsaSecretEncryptor(publicKey);

			return Constants.CIPHER + encryptor.encrypt(data);
		} catch (RuntimeException e) {
			throw new EncryptException("Erro ao criptografar a informação com chave pública", e);
		}
	}

	/**
	 * Valida o arquivo pelo conteudo, e nao pela extensao.
	 */
	private PublicKey readPublicKey(MultipartFile pemFile) {
		String pem;

		try {
			pem = new String(pemFile.getBytes(), StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new InvalidFileException("Não foi possível ler o arquivo pem", e);
		}

		if (!pem.contains(Constants.BEGIN_PUBLIC_KEY) || !pem.contains(Constants.END_PUBLIC_KEY)) {
			throw new InvalidFileException("O arquivo não é uma chave pública PEM (" + Constants.BEGIN_PUBLIC_KEY
					+ " ... " + Constants.END_PUBLIC_KEY + ")");
		}

		var base64 = pem.replace(Constants.BEGIN_PUBLIC_KEY, "").replace(Constants.END_PUBLIC_KEY, "")
				.replaceAll("\\s", "");

		try {
			var keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64));

			return KeyFactory.getInstance(Constants.RSA).generatePublic(keySpec);
		} catch (IllegalArgumentException | InvalidKeySpecException e) {
			throw new InvalidFileException("O arquivo não contém uma chave pública RSA válida", e);
		} catch (NoSuchAlgorithmException e) {
			throw new EncryptException("Algoritmo RSA indisponível", e);
		}
	}
}
