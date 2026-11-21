package com.example.cloudconfigpropserver.service;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Stream;

import org.springframework.cloud.config.server.environment.MultipleJGitEnvironmentRepository;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

/**
 * Lista as aplicacoes e os ambientes que possuem chave publica (.pem) no repositorio de
 * properties. Usado para montar as opcoes do /certificate/encrypt no Swagger.
 */
@Service
@Slf4j
public class PublicKeyCatalogService {

	/**
	 * Aplicacao e profile ficticios, usados so para atualizar o repositorio e descobrir a raiz dele.
	 */
	private static final String MARKER = "catalogo-de-chaves";

	private static final String APPLICATION_PLACEHOLDER = "{application}";

	private final MultipleJGitEnvironmentRepository repository;

	public PublicKeyCatalogService(MultipleJGitEnvironmentRepository repository) {
		this.repository = repository;
	}

	public String getDefaultLabel() {
		return repository.getDefaultLabel();
	}

	/**
	 * @return aplicacao -> ambientes com chave publica, em ordem alfabetica. Vazio se o
	 *         repositorio nao puder ser lido.
	 */
	public Map<String, List<String>> listApplications() {
		var applications = new TreeMap<String, List<String>>();

		try {
			var root = applicationsDirectory();

			if (root == null || !Files.isDirectory(root)) {
				return applications;
			}

			try (Stream<Path> apps = Files.list(root)) {
				apps.filter(Files::isDirectory).forEach(app -> {
					var profiles = profilesWithPublicKey(app);

					if (!profiles.isEmpty()) {
						applications.put(app.getFileName().toString(), profiles);
					}
				});
			}
		} catch (RuntimeException | IOException e) {
			log.warn("Não foi possível listar as chaves públicas do repositório de properties", e);
		}

		return applications;
	}

	/**
	 * Pasta onde ficam as aplicacoes no repositorio (ex.: properties/, para o search-path
	 * properties/{application}/{profile}).
	 */
	private Path applicationsDirectory() {
		var searchPath = Arrays.stream(repository.getSearchPaths()).filter(p -> p.contains(APPLICATION_PLACEHOLDER))
				.findFirst().orElse(null);

		if (searchPath == null) {
			return null;
		}

		// Atualiza o repositorio (mesmo pull das properties). Como a aplicacao ficticia nao existe,
		// so a raiz do repositorio e devolvida.
		var locations = repository.getLocations(MARKER, MARKER, null).getLocations();

		var repositoryRoot = Arrays.stream(locations).map(PublicKeyCatalogService::toPath)
				.min((a, b) -> Integer.compare(a.getNameCount(), b.getNameCount())).orElse(null);

		if (repositoryRoot == null) {
			return null;
		}

		return repositoryRoot.resolve(searchPath.substring(0, searchPath.indexOf(APPLICATION_PLACEHOLDER)));
	}

	private static List<String> profilesWithPublicKey(Path app) {
		var application = app.getFileName().toString();

		var profiles = new ArrayList<String>();

		try (Stream<Path> dirs = Files.list(app)) {
			dirs.filter(Files::isDirectory)
					.filter(dir -> Files.isRegularFile(
							dir.resolve(PemService.publicKeyFileName(application, dir.getFileName().toString()))))
					.forEach(dir -> profiles.add(dir.getFileName().toString()));
		} catch (IOException e) {
			log.warn("Não foi possível ler a pasta {}", app, e);
		}

		profiles.sort(null);

		return profiles;
	}

	private static Path toPath(String location) {
		var path = location.endsWith("/") ? location.substring(0, location.length() - 1) : location;

		return path.startsWith("file:") ? Path.of(URI.create(path)) : Path.of(path);
	}
}
