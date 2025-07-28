package com.example.cloudconfigpropserver.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;

import com.example.cloudconfigpropserver.model.AppFile;
import com.example.cloudconfigpropserver.model.Constants;

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
		var files = new ArrayList<AppFile>();

		var passwords = utilService.generatePasswordsByEnvironment();

		files.add(createPasswordFile(passwords));

		passwords.forEach((env, password) -> {
			try {
				var alias = applicationName + Constants.CLIENT_KEY + env;

				var result = certificateService.createFiles(alias, password);

				files.add(result.pfxFile());
				files.add(result.pemFile());
			} catch (Exception e) {
				var errorMessage = String.format("Erro ao gerar os arquivos da aplicação '%s' para o ambiente '%s'",
						applicationName, env);

				log.error(errorMessage, e);

				files.add(new AppFile(env + "-errors.txt", (errorMessage + ": " + e.getMessage()).getBytes()));
			}
		});

		return files;
	}

	private AppFile createPasswordFile(Map<String, String> passwords) {
		var builder = new StringBuilder();

		passwords.forEach((env, pass) -> builder.append(env).append("=").append(pass).append("\n"));

		return new AppFile("passwords.txt", builder.toString().getBytes());
	}
}