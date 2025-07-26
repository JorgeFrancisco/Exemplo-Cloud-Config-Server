package com.example.cloudconfigpropserver.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;

import com.example.cloudconfigpropserver.model.AppFile;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class GenerateFilesService {

	private final CertificateService certificateService;

	private final UtilService utilService;

	public GenerateFilesService(CertificateService certificateService, UtilService utilService) {
		this.certificateService = certificateService;
		this.utilService = utilService;
	}

	public List<AppFile> generateFiles(String applicationName) {
		List<AppFile> files = new ArrayList<>();

		var passwords = utilService.generatePasswordsByEnvironment();

		files.add(createPasswordFile(passwords));

		passwords.forEach((env, password) -> {
			try {
				String alias = applicationName + "-client-key-" + env;
				String fileName = alias + ".pfx";

				files.add(certificateService.createCertificate(alias, fileName, password));
			} catch (Exception e) {
				String errorMessage = String.format("Erro ao criar certificado da aplicação '%s' para o ambiente '%s'",
						applicationName, env);

				log.error(errorMessage, e);

				files.add(new AppFile(env + "-errors.txt", (errorMessage + ": " + e.getMessage()).getBytes()));
			}
		});

		return files;
	}

	private AppFile createPasswordFile(Map<String, String> passwords) {
		StringBuilder builder = new StringBuilder();
		passwords.forEach((env, pass) -> builder.append(env).append("=").append(pass).append("\n"));

		return new AppFile("passwords.txt", builder.toString().getBytes());
	}
}