package com.example.cloudconfigpropserver.config.properties;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotEmpty;

@Validated
@ConfigurationProperties(prefix = "cors")
public record CorsProperties(

		@NotEmpty(message = "A lista de allowedMethods não pode estar vazia") List<String> allowedMethods,
		@NotEmpty(message = "A lista de allowedHeaders não pode estar vazia") List<String> allowedHeaders,
		@NotEmpty(message = "A lista de exposedHeaders não pode estar vazia") List<String> exposedHeaders,
		@NotEmpty(message = "A lista de allowedOrigins não pode estar vazia") List<String> allowedOrigins) {
}