package com.example.cloudconfigpropserver.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import com.example.cloudconfigpropserver.exception.DecryptException;
import com.example.cloudconfigpropserver.exception.EncryptException;
import com.example.cloudconfigpropserver.service.CryptService;
import com.example.cloudconfigpropserver.service.GenerateFilesService;
import com.example.cloudconfigpropserver.service.UtilService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@RequestMapping("/certificate")
@Tag(description = "Conjunto de endpoints para gerenciamento dos certificados e dados das aplicações.", name = "Certificate")
public class CertificateController {

	private final GenerateFilesService generateFilesService;

	private final CryptService cryptService;

	private final UtilService utilService;

	@Autowired
	public CertificateController(GenerateFilesService generateFilesService, CryptService cryptService,
			UtilService utilService) {
		this.generateFilesService = generateFilesService;
		this.cryptService = cryptService;
		this.utilService = utilService;
	}

	@Operation(summary = "Cria os certificados para a aplicação e disponibiliza para download.", tags = "Certificate", responses = {
			@ApiResponse(responseCode = "200", description = "OK"),
			@ApiResponse(responseCode = "400", description = "Requisição inválida.", content = @Content),
			@ApiResponse(responseCode = "403", description = "Proibido acessar este recurso.", content = @Content),
			@ApiResponse(responseCode = "404", description = "Recurso não encontrado.", content = @Content),
			@ApiResponse(responseCode = "405", description = "Método HTTP não permitido.", content = @Content),
			@ApiResponse(responseCode = "500", description = "Erro no servidor.", content = @Content) })
	@PostMapping
	public ResponseEntity<StreamingResponseBody> generateCertificate(
			@RequestParam(name = "applicationName") @Parameter(description = "Nome da aplicação (spring.application.name do properties da aplicação)", required = true) String applicationName) {
		var files = generateFilesService.generateFiles(applicationName);

		var responseBody = utilService.generateZipFiles(files);

		var headers = getDownloadHeaders();

		return ResponseEntity.ok().headers(headers).body(responseBody);
	}

	@Operation(summary = "Criptografa o valor usando o certificado da aplicação para determinado ambiente.", tags = "Certificate", responses = {
			@ApiResponse(responseCode = "200", description = "OK"),
			@ApiResponse(responseCode = "400", description = "Requisição inválida.", content = @Content),
			@ApiResponse(responseCode = "403", description = "Proibido acessar este recurso.", content = @Content),
			@ApiResponse(responseCode = "404", description = "Recurso não encontrado.", content = @Content),
			@ApiResponse(responseCode = "405", description = "Método HTTP não permitido.", content = @Content),
			@ApiResponse(responseCode = "500", description = "Erro no servidor.", content = @Content) })
	@PostMapping(value = "/encrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<String> encrypt(
			@RequestPart("certificate") @Parameter(description = "Certificado .pfx") MultipartFile certificateFile,
			@RequestPart(name = "certificatePassword") @Parameter(description = "Senha do certificado", required = true) String certificatePassword,
			@RequestPart(name = "data") @Parameter(description = "Informação para criptografar", required = true) String data)
			throws EncryptException {
		String originalFilename = certificateFile.getOriginalFilename();

		if (originalFilename == null || !originalFilename.toLowerCase().endsWith(".pfx")) {
			return ResponseEntity.badRequest().body("Arquivo inválido ou sem extensão .pfx");
		}

		final var aliasName = originalFilename.substring(0, originalFilename.lastIndexOf('.'));

		return ResponseEntity.ok().body(cryptService.encrypt(certificateFile, certificatePassword, aliasName, data));
	}

	@Operation(summary = "Descriptografa o valor usando o certificado da aplicação para determinado ambiente.", tags = "Certificate", responses = {
			@ApiResponse(responseCode = "200", description = "OK"),
			@ApiResponse(responseCode = "400", description = "Requisição inválida.", content = @Content),
			@ApiResponse(responseCode = "403", description = "Proibido acessar este recurso.", content = @Content),
			@ApiResponse(responseCode = "404", description = "Recurso não encontrado.", content = @Content),
			@ApiResponse(responseCode = "405", description = "Método HTTP não permitido.", content = @Content),
			@ApiResponse(responseCode = "500", description = "Erro no servidor.", content = @Content) })
	@PostMapping(value = "/decrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<String> decrypt(
			@RequestPart("certificate") @Parameter(description = "Certificado .pfx") MultipartFile certificateFile,
			@RequestPart(name = "certificatePassword") @Parameter(description = "Senha do certificado", required = true) String certificatePassword,
			@RequestPart(name = "data") @Parameter(description = "Informação para criptografar", required = true) String data)
			throws DecryptException {
		String originalFilename = certificateFile.getOriginalFilename();

		if (originalFilename == null || !originalFilename.toLowerCase().endsWith(".pfx")) {
			return ResponseEntity.badRequest().body("Arquivo inválido ou sem extensão .pfx");
		}

		final var aliasName = originalFilename.substring(0, originalFilename.lastIndexOf('.'));

		return ResponseEntity.ok().body(cryptService.decrypt(certificateFile, certificatePassword, aliasName, data));
	}

	private HttpHeaders getDownloadHeaders() {
		var headers = new HttpHeaders();

		headers.add("Content-Type", "application/zip");
		headers.add("Content-Disposition", "attachment; filename=download.zip");
		headers.add("Pragma", "no-cache");
		headers.add("Cache-Control", "no-cache");

		return headers;
	}
}