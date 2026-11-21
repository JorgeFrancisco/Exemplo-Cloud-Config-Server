package com.example.cloudconfigpropserver.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.cloud.config.server.environment.NoSuchLabelException;
import org.springframework.cloud.config.server.resource.NoSuchResourceException;
import org.springframework.cloud.config.server.resource.ResourceRepository;
import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.example.cloudconfigpropserver.exception.EncryptException;
import com.example.cloudconfigpropserver.exception.InvalidFileException;
import com.example.cloudconfigpropserver.exception.PublicKeyNotFoundException;
import com.example.cloudconfigpropserver.model.Constants;

@Service
public class PemService {

	private final ResourceRepository resourceRepository;

	public PemService(ResourceRepository resourceRepository) {
		this.resourceRepository = resourceRepository;
	}

	/**
	 * Criptografa usando somente a chave publica. A chave privada continua apenas com a
	 * aplicacao client, que e quem descriptografa.
	 */
	public String encrypt(MultipartFile pemFile, String data) {
		String pem;

		try {
			pem = new String(pemFile.getBytes(), StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new InvalidFileException("Não foi possível ler o arquivo pem", e);
		}

		return encrypt(readPublicKey(pem), data);
	}

	/**
	 * Criptografa usando a chave publica guardada no repositorio de properties, na pasta da
	 * aplicacao e do ambiente: properties/{aplicacao}/{profile}/{aplicacao}-client-key-{profile}.pem.
	 * O arquivo e buscado pelo proprio Config Server (mesmo repositorio, search-paths e label das
	 * properties), entao quem criptografa nao precisa ter o arquivo.
	 *
	 * @param label branch do repositorio; se vazio, usa a branch padrao do servidor
	 */
	public String encrypt(String application, String profile, String label, String data) {
		validateName("applicationName", application);
		validateName("profile", profile);

		var fileName = publicKeyFileName(application, profile);

		String pem;

		try {
			var resource = resourceRepository.findOne(application, profile, label, fileName);

			pem = resource.getContentAsString(StandardCharsets.UTF_8);
		} catch (NoSuchResourceException | NoSuchLabelException e) {
			throw new PublicKeyNotFoundException("Chave pública não encontrada no repositório de properties: properties/"
					+ application + "/" + profile + "/" + fileName + (label == null ? "" : " (branch " + label + ")"), e);
		} catch (IOException e) {
			throw new EncryptException("Erro ao ler a chave pública do repositório de properties", e);
		}

		return encrypt(readPublicKey(pem), data);
	}

	public static String publicKeyFileName(String application, String profile) {
		return application + Constants.CLIENT_KEY + profile + Constants.PEM;
	}

	/**
	 * O nome da aplicacao e o profile fazem parte do caminho do arquivo no repositorio, entao so
	 * sao aceitos nomes simples (sem barras nem "..").
	 */
	private static void validateName(String field, String value) {
		if (value == null || !value.matches(Constants.SIMPLE_NAME_REGEX) || value.contains("..")) {
			throw new InvalidFileException(
					"Valor inválido para " + field + ": use somente letras, números, ponto, hífen e sublinhado");
		}
	}

	private String encrypt(PublicKey publicKey, String data) {
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
	private PublicKey readPublicKey(String pem) {
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
