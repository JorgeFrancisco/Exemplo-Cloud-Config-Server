package com.example.cloudconfigpropserver.service;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.example.cloudconfigpropserver.exception.CertificateGenerationException;
import com.example.cloudconfigpropserver.exception.EncryptException;
import com.example.cloudconfigpropserver.model.Constants;

@Service
public class PemService {

	public String encrypt(MultipartFile pemFile, String data) throws CertificateGenerationException {
		try {
			var pem = new String(pemFile.getBytes(), StandardCharsets.UTF_8);

			var base64 = pem.replace(Constants.BEGIN_PUBLIC_KEY, "").replace(Constants.END_PUBLIC_KEY, "")
					.replaceAll("\\s", "");

			var keyBytes = Base64.getDecoder().decode(base64);

			var keySpec = new X509EncodedKeySpec(keyBytes);

			var keyFactory = KeyFactory.getInstance(Constants.RSA);

			var publicKey = keyFactory.generatePublic(keySpec);

			var encryptor = new RsaSecretEncryptor(publicKey);

			return Constants.CIPHER + encryptor.encrypt(data);
		} catch (Exception e) {
			throw new EncryptException("Erro ao criptografar a informação com chave pública", e);
		}
	}
}