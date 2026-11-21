package com.example.cloudconfigpropserver.config.swagger;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.stream.Collectors;

import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;

import com.example.cloudconfigpropserver.config.properties.ServletProperties;
import com.example.cloudconfigpropserver.controller.CertificateController;
import com.example.cloudconfigpropserver.service.PublicKeyCatalogService;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.servers.Server;

@Configuration
public class SwaggerConfig {

	static final String ENCRYPT_PATH = "/certificate/encrypt";

	private static final List<String> DEFAULT_PROFILES = List.of("development", "staging", "production");

	private final BuildProperties buildProperties;

	private final ServletProperties servletProperties;

	private final PublicKeyCatalogService publicKeyCatalogService;

	@Autowired
	public SwaggerConfig(BuildProperties buildProperties, ServletProperties servletProperties,
			PublicKeyCatalogService publicKeyCatalogService) {
		this.buildProperties = buildProperties;
		this.servletProperties = servletProperties;
		this.publicKeyCatalogService = publicKeyCatalogService;
	}

	@Bean
	public GroupedOpenApi cloudConfigGroupedOpenApi() {
		return GroupedOpenApi.builder().group("Spring Cloud Config").pathsToMatch("/certificate/**")
				.addOpenApiCustomizer(cloudConfigOpenApiCustomiser()).addOpenApiCustomizer(encryptOptionsCustomizer())
				.packagesToScan(CertificateController.class.getPackageName()).build();
	}

	public OpenApiCustomizer cloudConfigOpenApiCustomiser() {
		return openApi -> openApi.info(cloudConfigInfo())
				.servers(Arrays.asList(new Server().url(servletProperties.contextPath())));
	}

	/**
	 * Preenche as opcoes (combos) do /certificate/encrypt com o que existe no repositorio de
	 * properties: as aplicacoes que possuem chave publica, os ambientes e a branch padrao. Como o
	 * cache do springdoc esta desligado, as opcoes sao atualizadas a cada carregamento do Swagger.
	 */
	public OpenApiCustomizer encryptOptionsCustomizer() {
		return openApi -> {
			var form = encryptFormSchema(openApi);

			if (form == null || form.getProperties() == null) {
				return;
			}

			var applications = publicKeyCatalogService.listApplications();

			var profiles = new TreeSet<String>();
			applications.values().forEach(profiles::addAll);

			setEnum(form.getProperties().get("applicationName"), new ArrayList<>(applications.keySet()));
			setEnum(form.getProperties().get("profile"),
					profiles.isEmpty() ? DEFAULT_PROFILES : new ArrayList<>(profiles));

			Schema<?> label = form.getProperties().get("label");

			if (label != null) {
				label.setDefault(publicKeyCatalogService.getDefaultLabel());
			}

			var operation = openApi.getPaths().get(ENCRYPT_PATH).getPost();

			operation.setDescription(describe(applications));
		};
	}

	private static Schema<?> encryptFormSchema(OpenAPI openApi) {
		if (openApi.getPaths() == null || openApi.getPaths().get(ENCRYPT_PATH) == null
				|| openApi.getPaths().get(ENCRYPT_PATH).getPost() == null
				|| openApi.getPaths().get(ENCRYPT_PATH).getPost().getRequestBody() == null) {
			return null;
		}

		var media = openApi.getPaths().get(ENCRYPT_PATH).getPost().getRequestBody().getContent()
				.get(MediaType.MULTIPART_FORM_DATA_VALUE);

		if (media == null || media.getSchema() == null) {
			return null;
		}

		Schema<?> schema = media.getSchema();

		if (schema.get$ref() != null && openApi.getComponents() != null
				&& openApi.getComponents().getSchemas() != null) {
			schema = openApi.getComponents().getSchemas().get(schema.get$ref().replace("#/components/schemas/", ""));
		}

		return schema;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private static void setEnum(Schema schema, List<String> values) {
		if (schema != null && !values.isEmpty()) {
			schema.setEnum(values);
		}
	}

	private static String describe(Map<String, List<String>> applications) {
		if (applications.isEmpty()) {
			return "Nenhuma aplicação possui chave pública no repositório de properties. Guarde o .pem em"
					+ " properties/{aplicacao}/{profile}/{aplicacao}-client-key-{profile}.pem.";
		}

		return "Aplicações e ambientes com chave pública no repositório de properties: "
				+ applications.entrySet().stream().map(e -> e.getKey() + " (" + String.join(", ", e.getValue()) + ")")
						.collect(Collectors.joining("; "))
				+ ".";
	}

	private Info cloudConfigInfo() {
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy.MM.dd.HH.mm.ss.SSS");
		String formattedString = buildProperties.getTime().atZone(ZoneId.of("America/Sao_Paulo")).format(formatter);

		return new Info().title("API - Spring Cloud Config Server")
				.description("Documentação da API do Spring Cloud Config Server.")
				.version(buildProperties.getVersion() + "-" + formattedString)
				.license(new License().name("Apache License Version 2.0")
						.url("https://www.apache.org/licenses/LICENSE-2.0"))
				.contact(new Contact().name("JFBM").url("http://www.jfbm.tech.br").email("contato@jfbm.tech.br"));
	}
}
