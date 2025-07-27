package com.example.cloudconfigpropserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.cloud.config.server.EnableConfigServer;

import com.example.cloudconfigpropserver.config.properties.ServletProperties;

@SpringBootApplication
@EnableConfigServer
@ConfigurationPropertiesScan(basePackageClasses = ServletProperties.class)
public class CloudConfigPropServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(CloudConfigPropServerApplication.class, args);
	}
}