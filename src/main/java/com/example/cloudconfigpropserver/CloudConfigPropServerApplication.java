package com.example.cloudconfigpropserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.cloud.config.server.EnableConfigServer;

import com.example.cloudconfigpropserver.config.properties.ServletProperties;

// A API nao autentica usuarios (as regras ficam na SecurityConfiguration), entao o usuario
// padrao com senha gerada no boot nao e necessario.
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
@EnableConfigServer
@ConfigurationPropertiesScan(basePackageClasses = ServletProperties.class)
public class CloudConfigPropServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(CloudConfigPropServerApplication.class, args);
	}
}