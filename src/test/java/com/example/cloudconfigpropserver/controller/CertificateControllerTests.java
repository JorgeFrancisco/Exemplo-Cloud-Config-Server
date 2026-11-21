package com.example.cloudconfigpropserver.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipInputStream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CertificateControllerTests {

	private static final String ALIAS = "app-client-key-development";

	@Autowired
	private MockMvc mockMvc;

	private byte[] pfx;

	private byte[] pem;

	private String password;

	@BeforeAll
	void gerarArquivos() throws Exception {
		var zip = mockMvc.perform(post("/certificate").param("applicationName", "app")).andExpect(status().isOk())
				.andReturn();

		var files = unzip(mockMvc.perform(asyncDispatch(zip)).andReturn().getResponse().getContentAsByteArray());

		assertThat(files).containsKeys("passwords.txt", ALIAS + ".pfx", ALIAS + ".pem");

		pfx = files.get(ALIAS + ".pfx");
		pem = files.get(ALIAS + ".pem");
		password = new String(files.get("passwords.txt"), StandardCharsets.UTF_8).lines()
				.filter(l -> l.startsWith("development=")).findFirst().orElseThrow().substring("development=".length());
	}

	@Test
	void deveCriptografarComChavePublicaEDescriptografarComAPrivada() throws Exception {
		// Nome sem extensao .pem: a validacao e pelo conteudo
		var cipher = mockMvc
				.perform(multipart("/certificate/pem/encrypt").file(new MockMultipartFile("pemFile", "chave", null, pem))
						.file(part("data", "segredo")))
				.andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

		assertThat(cipher).startsWith("{cipher}");

		var keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(new ByteArrayInputStream(pfx), password.toCharArray());

		var keyPair = new KeyPair(keyStore.getCertificate(ALIAS).getPublicKey(),
				(PrivateKey) keyStore.getKey(ALIAS, password.toCharArray()));

		assertThat(new RsaSecretEncryptor(keyPair).decrypt(cipher.substring("{cipher}".length()))).isEqualTo("segredo");
	}

	@Test
	void deveRecusarArquivoQueNaoEChavePublica() throws Exception {
		mockMvc.perform(multipart("/certificate/pem/encrypt")
				.file(new MockMultipartFile("pemFile", "chave.pem", null, "nao e uma chave".getBytes()))
				.file(part("data", "segredo"))).andExpect(status().isBadRequest());
	}

	@Test
	void naoDeveMaisExistirEncryptComPfx() throws Exception {
		mockMvc.perform(multipart("/certificate/pfx/encrypt").file(new MockMultipartFile("pfxFile", ALIAS + ".pfx", null, pfx))
				.file(part("password", password)).file(part("data", "segredo"))).andExpect(status().isNotFound());
	}

	@Test
	void deveExportarChavePublicaMesmoComPfxRenomeado() throws Exception {
		var result = mockMvc.perform(multipart("/certificate/pfx/public-key/export")
				.file(new MockMultipartFile("pfxFile", "renomeado (1).pfx", null, pfx)).file(part("password", password)))
				.andExpect(status().isOk()).andReturn();

		var files = unzip(mockMvc.perform(asyncDispatch(result)).andReturn().getResponse().getContentAsByteArray());

		// O nome do pem vem do alias de dentro do pfx, e nao do nome do arquivo enviado
		assertThat(files).containsOnlyKeys(ALIAS + ".pem");
		assertThat(files.get(ALIAS + ".pem")).isEqualTo(pem);
	}

	@Test
	void deveListarAliases() throws Exception {
		mockMvc.perform(multipart("/certificate/pfx/list-aliases").file(new MockMultipartFile("pfxFile", "x", null, pfx))
				.file(part("password", password))).andExpect(status().isOk()).andExpect(jsonPath("$[0]").value(ALIAS))
				.andExpect(jsonPath("$.length()").value(1));
	}

	@Test
	void deveRecusarSenhaIncorretaComMensagem() throws Exception {
		mockMvc.perform(multipart("/certificate/pfx/list-aliases").file(new MockMultipartFile("pfxFile", "x", null, pfx))
				.file(part("password", "senha-errada"))).andExpect(status().isBadRequest())
				.andExpect(content().string("Arquivo pfx inválido ou senha incorreta"));
	}

	private static MockMultipartFile part(String name, String value) {
		return new MockMultipartFile(name, null, "text/plain", value.getBytes(StandardCharsets.UTF_8));
	}

	private static Map<String, byte[]> unzip(byte[] zip) throws IOException {
		var files = new HashMap<String, byte[]>();

		try (var zis = new ZipInputStream(new ByteArrayInputStream(zip))) {
			for (var entry = zis.getNextEntry(); entry != null; entry = zis.getNextEntry()) {
				files.put(entry.getName(), zis.readAllBytes());
			}
		}

		return files;
	}
}
