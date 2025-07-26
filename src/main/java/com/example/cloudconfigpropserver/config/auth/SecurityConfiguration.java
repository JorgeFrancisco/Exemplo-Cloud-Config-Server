package com.example.cloudconfigpropserver.config.auth;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter.HeaderValue;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfiguration {

	private static final String CSP = "default-src 'self' data:";

	@Value("${cors.allowed-methods}")
	private List<String> allowedMethods;

	@Value("${cors.allowed-headers}")
	private List<String> allowedHeaders;

	@Value("${cors.exposed-headers}")
	private List<String> exposedHeaders;

	@Value("${cors.allowed-origins}")
	private List<String> allowedOrigins;

	private static final String[] AUTH_WHITELIST = {
			// @formatter:off
			"/**.html",
			"/configuration/**",
			"/h2-console/**",
			"/actuator/**",
			"/",
			// -- Swagger UI v2
			"/v2/api-docs",
			"/swagger-resources",
			"/swagger-resources/**",
			"/configuration/ui",
			"/configuration/security",
			"/swagger-ui.html",
			"/webjars/**",
			// -- Swagger UI v3 (OpenAPI)
			"/v3/api-docs/**",
			"/swagger-ui/**",
			// -- Spring config
			"/config/encrypt/**",
			// -- Custom
			"/certificate/**"
			// @formatter:on
	};

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.csrf(AbstractHttpConfigurer::disable)
				.headers(headers -> headers.xssProtection(xss -> xss.headerValue(HeaderValue.ENABLED_MODE_BLOCK))
						.contentSecurityPolicy(cps -> cps.policyDirectives(CSP)));

		http.cors(
				httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource()))
				.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(authorizeRequests -> authorizeRequests.requestMatchers(AUTH_WHITELIST)
						.permitAll().requestMatchers("/config/decrypt/**").denyAll());

		return http.build();

	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration corsConfiguration = new CorsConfiguration();

		corsConfiguration.setAllowedMethods(allowedMethods);
		corsConfiguration.setAllowedHeaders(allowedHeaders);
		corsConfiguration.setExposedHeaders(exposedHeaders);
		corsConfiguration.setAllowedOrigins(allowedOrigins);

		corsConfiguration.setAllowCredentials(true);

		corsConfiguration.setMaxAge(3600L);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

		source.registerCorsConfiguration("/**", corsConfiguration);

		return source;
	}
}