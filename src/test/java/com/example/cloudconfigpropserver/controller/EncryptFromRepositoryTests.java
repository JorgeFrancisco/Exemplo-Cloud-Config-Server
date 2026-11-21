package com.example.cloudconfigpropserver.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;

import org.eclipse.jgit.api.Git;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMultipartHttpServletRequestBuilder;

import com.example.cloudconfigpropserver.model.CertificateResult;
import com.example.cloudconfigpropserver.service.CertificateService;
import com.example.cloudconfigpropserver.service.PfxService;

/**
 * Testa o /certificate/encrypt, que busca a chave publica no repositorio de properties. Usa um
 * repositorio Git temporario no lugar do repositorio real.
 */
@SpringBootTest
@AutoConfigureMockMvc
class EncryptFromRepositoryTests {

	private static final String APP = "app";

	private static final String ALIAS = APP + "-client-key-development";

	private static final String PASSWORD = "senha-de-teste";

	private static CertificateResult certificate;

	@Autowired
	private MockMvc mockMvc;

	@DynamicPropertySource
	static void repositorioDeProperties(DynamicPropertyRegistry registry) throws Exception {
		certificate = new CertificateService(new PfxService()).createFiles(ALIAS, PASSWORD);

		Path repo = Files.createTempDirectory("properties-repo");
		Path pasta = Files.createDirectories(repo.resolve("properties/" + APP + "/development"));

		Files.writeString(pasta.resolve("application.properties"), "app.name=Teste\n");
		Files.write(pasta.resolve(ALIAS + ".pem"), certificate.pemFile().getContent());

		try (var git = Git.init().setDirectory(repo.toFile()).setInitialBranch("main").call()) {
			git.add().addFilepattern(".").call();
			git.commit().setMessage("properties").setAuthor("teste", "teste@teste").setCommitter("teste", "teste@teste")
					.setSign(false).call();
		}

		registry.add("spring.cloud.config.server.git.uri", () -> repo.toUri().toString());
		registry.add("spring.cloud.config.server.git.default-label", () -> "main");
	}

	@Test
	void deveCriptografarComAChavePublicaDoRepositorio() throws Exception {
		var cipher = mockMvc.perform(encrypt(APP, "development", null)).andExpect(status().isOk()).andReturn()
				.getResponse().getContentAsString();

		assertThat(cipher).startsWith("{cipher}");

		var keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(new ByteArrayInputStream(certificate.pfxFile().getContent()), PASSWORD.toCharArray());

		var keyPair = new KeyPair(keyStore.getCertificate(ALIAS).getPublicKey(),
				(PrivateKey) keyStore.getKey(ALIAS, PASSWORD.toCharArray()));

		assertThat(new RsaSecretEncryptor(keyPair).decrypt(cipher.substring("{cipher}".length()))).isEqualTo("segredo");
	}

	@Test
	void deveAceitarBranchInformada() throws Exception {
		mockMvc.perform(encrypt(APP, "development", "main")).andExpect(status().isOk());
	}

	@Test
	void deveInformarQuandoAChavePublicaNaoExiste() throws Exception {
		mockMvc.perform(encrypt(APP, "staging", null)).andExpect(status().isNotFound())
				.andExpect(content().string(Matchers.containsString("properties/app/staging/app-client-key-staging.pem")));
	}

	@Test
	void deveInformarQuandoABranchNaoExiste() throws Exception {
		mockMvc.perform(encrypt(APP, "development", "branch-inexistente")).andExpect(status().isNotFound());
	}

	@Test
	void deveRecusarNomeQueSaiDaPastaDaAplicacao() throws Exception {
		mockMvc.perform(encrypt("../" + APP, "development", null)).andExpect(status().isBadRequest());
	}

	@Test
	void naoDeveEntregarAChavePublicaComoPropertyDaAplicacao() throws Exception {
		// O Config Server so carrega application*.properties/yml; o .pem na mesma pasta e ignorado
		mockMvc.perform(get("/config/" + APP + "/development")).andExpect(status().isOk())
				.andExpect(jsonPath("$.propertySources.length()").value(1))
				.andExpect(jsonPath("$.propertySources[0].name").value(Matchers.endsWith("application.properties")))
				.andExpect(jsonPath("$.propertySources[0].source['app.name']").value("Teste"));
	}

	private static MockMultipartHttpServletRequestBuilder encrypt(String app, String profile, String label) {
		var request = multipart("/certificate/encrypt").file(part("applicationName", app)).file(part("profile", profile))
				.file(part("data", "segredo"));

		return label == null ? request : request.file(part("label", label));
	}

	private static MockMultipartFile part(String name, String value) {
		return new MockMultipartFile(name, null, "text/plain", value.getBytes(StandardCharsets.UTF_8));
	}
}
