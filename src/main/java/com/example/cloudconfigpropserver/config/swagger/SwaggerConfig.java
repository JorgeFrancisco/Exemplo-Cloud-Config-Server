package com.example.cloudconfigpropserver.config.swagger;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;

import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.example.cloudconfigpropserver.controller.CertificateController;

import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;

@Configuration
public class SwaggerConfig {

	private final BuildProperties buildProperties;

	@Autowired
	public SwaggerConfig(BuildProperties buildProperties) {
		this.buildProperties = buildProperties;
	}

	@Value("${server.servlet.context-path}")
	String contextPath;

	@Bean
	public GroupedOpenApi cloudConfigGroupedOpenApi() {
		return GroupedOpenApi.builder().group("Spring Cloud Config").pathsToMatch("/certificate/**")
				.addOpenApiCustomizer(cloudConfigOpenApiCustomiser())
				.packagesToScan(CertificateController.class.getPackageName()).build();
	}

	public OpenApiCustomizer cloudConfigOpenApiCustomiser() {
		return openApi -> openApi.info(cloudConfigInfo()).servers(Arrays.asList(new Server().url(contextPath)));
	}

	private Info cloudConfigInfo() {
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy.MM.dd.HH.mm.ss.SSS");
		String formattedString = buildProperties.getTime().atZone(ZoneId.of("America/Sao_Paulo")).format(formatter);

		return new Info().title("API - Spring Cloud Config Server")
				.description("Documentação da API do Spring Cloud Config Server.")
				.version(buildProperties.getVersion() + "-" + formattedString)
				.license(new License().name("Apache License Version 2.0")
						.url("https://www.apache.org/licenses/LICENSE-2.0\""))
				.contact(new Contact().name("JFBM").url("http://www.jfbm.tech.br").email("contato@jfbm.tech.br"));
	}
}