package com.example.cloudconfigpropserver.controller;

import java.util.ArrayList;
import java.util.List;

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
import com.example.cloudconfigpropserver.model.Constants;
import com.example.cloudconfigpropserver.service.CertificateService;
import com.example.cloudconfigpropserver.service.GenerateFilesService;
import com.example.cloudconfigpropserver.service.PemService;
import com.example.cloudconfigpropserver.service.PfxService;
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

	private final UtilService utilService;

	private final CertificateService certificateService;

	private final PfxService pfxService;

	private final PemService pemService;

	@Autowired
	public CertificateController(GenerateFilesService generateFilesService, UtilService utilService,
			CertificateService certificateService, PfxService pfxService, PemService pemService) {
		this.generateFilesService = generateFilesService;
		this.utilService = utilService;
		this.certificateService = certificateService;
		this.pfxService = pfxService;
		this.pemService = pemService;
	}

	@Operation(summary = "Cria os arquivos para a aplicação, com os certificados, chaves públicas e senhas, e disponibiliza para download.", tags = "Certificate", responses = {
			@ApiResponse(responseCode = "200", description = "OK"),
			@ApiResponse(responseCode = "400", description = "Requisição inválida.", content = @Content),
			@ApiResponse(responseCode = "403", description = "Proibido acessar este recurso.", content = @Content),
			@ApiResponse(responseCode = "404", description = "Recurso não encontrado.", content = @Content),
			@ApiResponse(responseCode = "405", description = "Método HTTP não permitido.", content = @Content),
			@ApiResponse(responseCode = "500", description = "Erro no servidor.", content = @Content) })
	@PostMapping
	public ResponseEntity<StreamingResponseBody> generateFiles(
			@RequestParam(name = "applicationName") @Parameter(description = "Nome da aplicação (spring.application.name do properties da aplicação)", required = true) String applicationName) {
		var files = generateFilesService.generateFiles(applicationName);

		var responseBody = utilService.generateZipFiles(files);

		var headers = getDownloadHeaders("CertificadosEOutros");

		return ResponseEntity.ok().headers(headers).body(responseBody);
	}

	@Operation(summary = "Criptografa o valor informado usando o arquivo pfx da aplicação para determinado ambiente.", tags = "Certificate", responses = {
			@ApiResponse(responseCode = "200", description = "OK"),
			@ApiResponse(responseCode = "400", description = "Requisição inválida.", content = @Content),
			@ApiResponse(responseCode = "403", description = "Proibido acessar este recurso.", content = @Content),
			@ApiResponse(responseCode = "404", description = "Recurso não encontrado.", content = @Content),
			@ApiResponse(responseCode = "405", description = "Método HTTP não permitido.", content = @Content),
			@ApiResponse(responseCode = "500", description = "Erro no servidor.", content = @Content) })
	@PostMapping(value = "/pfx/encrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<String> encryptPfx(
			@RequestPart("pfxFile") @Parameter(description = "Arquivo .pfx") MultipartFile pfxFile,
			@RequestPart(name = "password") @Parameter(description = "Senha do arquivo pfx", required = true) String password,
			@RequestPart(name = "data") @Parameter(description = "Informação para criptografar", required = true) String data)
			throws EncryptException {
		var alias = pfxService.extractAlias(pfxFile);

		var encrypted = pfxService.encrypt(pfxFile, password, alias, data);

		return ResponseEntity.ok(encrypted);
	}

	@Operation(summary = "Criptografa o valor informado usando a chave pública da aplicação para determinado ambiente.", tags = "Certificate", responses = {
			@ApiResponse(responseCode = "200", description = "OK"),
			@ApiResponse(responseCode = "400", description = "Requisição inválida.", content = @Content),
			@ApiResponse(responseCode = "403", description = "Proibido acessar este recurso.", content = @Content),
			@ApiResponse(responseCode = "404", description = "Recurso não encontrado.", content = @Content),
			@ApiResponse(responseCode = "405", description = "Método HTTP não permitido.", content = @Content),
			@ApiResponse(responseCode = "500", description = "Erro no servidor.", content = @Content) })
	@PostMapping(value = "/pem/encrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<String> encryptPem(
			@RequestPart("pemFile") @Parameter(description = "Chave pública .pem") MultipartFile pemFile,
			@RequestPart(name = "data") @Parameter(description = "Informação para criptografar", required = true) String data)
			throws EncryptException {
		String originalFilename = pemFile.getOriginalFilename();

		if (originalFilename == null || !originalFilename.toLowerCase().endsWith(Constants.PEM)) {
			return ResponseEntity.badRequest().body("Arquivo inválido ou sem extensão .pem");
		}

		var encrypted = pemService.encrypt(pemFile, data);

		return ResponseEntity.ok(encrypted);
	}

	@Operation(summary = "Descriptografa o valor usando o arquivo pfx da aplicação para determinado ambiente.", tags = "Certificate", responses = {
			@ApiResponse(responseCode = "200", description = "OK"),
			@ApiResponse(responseCode = "400", description = "Requisição inválida.", content = @Content),
			@ApiResponse(responseCode = "403", description = "Proibido acessar este recurso.", content = @Content),
			@ApiResponse(responseCode = "404", description = "Recurso não encontrado.", content = @Content),
			@ApiResponse(responseCode = "405", description = "Método HTTP não permitido.", content = @Content),
			@ApiResponse(responseCode = "500", description = "Erro no servidor.", content = @Content) })
	@PostMapping(value = "/decrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<String> decrypt(
			@RequestPart("pfxFile") @Parameter(description = "Arquivo .pfx") MultipartFile pfxFile,
			@RequestPart(name = "password") @Parameter(description = "Senha do arquivo pfx", required = true) String password,
			@RequestPart(name = "data") @Parameter(description = "Informação para descriptografar", required = true) String data)
			throws DecryptException {
		String originalFilename = pfxFile.getOriginalFilename();

		if (originalFilename == null || !originalFilename.toLowerCase().endsWith(Constants.PFX)) {
			return ResponseEntity.badRequest().body("Arquivo inválido ou sem extensão .pfx");
		}

		final var alias = originalFilename.substring(0, originalFilename.lastIndexOf('.'));

		var decrypted = pfxService.decrypt(pfxFile, password, alias, data);

		return ResponseEntity.ok(decrypted);
	}

	@Operation(summary = "Exporta a chave pública do arquivo pfx.", tags = "Certificate", responses = {
			@ApiResponse(responseCode = "200", description = "OK"),
			@ApiResponse(responseCode = "400", description = "Requisição inválida.", content = @Content),
			@ApiResponse(responseCode = "403", description = "Proibido acessar este recurso.", content = @Content),
			@ApiResponse(responseCode = "404", description = "Recurso não encontrado.", content = @Content),
			@ApiResponse(responseCode = "405", description = "Método HTTP não permitido.", content = @Content),
			@ApiResponse(responseCode = "500", description = "Erro no servidor.", content = @Content) })
	@PostMapping(value = "/pfx/public-key/export", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<StreamingResponseBody> exportPublicKeyPfx(
			@RequestPart("pfxFile") @Parameter(description = "Arquivo .pfx") MultipartFile pfxFile,
			@RequestPart(name = "password") @Parameter(description = "Senha do arquivo pfx", required = true) String password)
			throws EncryptException {
		var alias = pfxService.extractAlias(pfxFile);

		var publicKey = pfxService.exportPublicKeyAsPem(pfxFile, password, alias);

		var responseBody = utilService.generateZipFiles(List.of(publicKey));

		var headers = getDownloadHeaders("ChavePublica");

		return ResponseEntity.ok().headers(headers).body(responseBody);
	}

	@Operation(summary = "Lista os aliases do arquivo pfx.", tags = "Certificate", responses = {
			@ApiResponse(responseCode = "200", description = "OK"),
			@ApiResponse(responseCode = "400", description = "Requisição inválida.", content = @Content),
			@ApiResponse(responseCode = "403", description = "Proibido acessar este recurso.", content = @Content),
			@ApiResponse(responseCode = "404", description = "Recurso não encontrado.", content = @Content),
			@ApiResponse(responseCode = "405", description = "Método HTTP não permitido.", content = @Content),
			@ApiResponse(responseCode = "500", description = "Erro no servidor.", content = @Content) })
	@PostMapping(value = "/pfx/list-aliases", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<List<String>> listAliases(
			@RequestPart("pfxFile") @Parameter(description = "Arquivo .pfx") MultipartFile pfxFile,
			@RequestPart(name = "password") @Parameter(description = "Senha do arquivo pfx", required = true) String password) {
		try {
			var aliases = certificateService.listAliases(pfxFile, password);

			var aliasList = new ArrayList<String>();

			while (aliases.hasMoreElements()) {
				aliasList.add(aliases.nextElement());
			}

			return ResponseEntity.ok(aliasList);
		} catch (Exception e) {
			return ResponseEntity.badRequest().build();
		}
	}

	private HttpHeaders getDownloadHeaders(String fileName) {
		var headers = new HttpHeaders();

		headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
		headers.set(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + fileName + Constants.ZIP);
		headers.setPragma("no-cache");
		headers.setCacheControl("no-cache");

		return headers;
	}
}