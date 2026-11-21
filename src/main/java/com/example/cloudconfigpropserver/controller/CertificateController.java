package com.example.cloudconfigpropserver.controller;

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

import com.example.cloudconfigpropserver.model.Constants;
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

	private final PfxService pfxService;

	private final PemService pemService;

	@Autowired
	public CertificateController(GenerateFilesService generateFilesService, UtilService utilService,
			PfxService pfxService, PemService pemService) {
		this.generateFilesService = generateFilesService;
		this.utilService = utilService;
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

	@Operation(summary = "Criptografa o valor informado usando a chave pública (.pem) da aplicação para determinado ambiente."
			+ " A chave privada (.pfx) não é necessária, ela fica somente com a aplicação client.", tags = "Certificate", responses = {
			@ApiResponse(responseCode = "200", description = "OK"),
			@ApiResponse(responseCode = "400", description = "Requisição inválida.", content = @Content),
			@ApiResponse(responseCode = "403", description = "Proibido acessar este recurso.", content = @Content),
			@ApiResponse(responseCode = "404", description = "Recurso não encontrado.", content = @Content),
			@ApiResponse(responseCode = "405", description = "Método HTTP não permitido.", content = @Content),
			@ApiResponse(responseCode = "500", description = "Erro no servidor.", content = @Content) })
	@PostMapping(value = "/pem/encrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<String> encryptPem(
			@RequestPart("pemFile") @Parameter(description = "Chave pública .pem") MultipartFile pemFile,
			@RequestPart(name = "data") @Parameter(description = "Informação para criptografar", required = true) String data) {
		var encrypted = pemService.encrypt(pemFile, data);

		return ResponseEntity.ok(encrypted);
	}

	@Operation(summary = "Exporta a chave pública (.pem) do arquivo pfx, para quem tiver somente o pfx."
			+ " O alias é lido de dentro do pfx, o nome do arquivo não importa.", tags = "Certificate", responses = {
			@ApiResponse(responseCode = "200", description = "OK"),
			@ApiResponse(responseCode = "400", description = "Requisição inválida.", content = @Content),
			@ApiResponse(responseCode = "403", description = "Proibido acessar este recurso.", content = @Content),
			@ApiResponse(responseCode = "404", description = "Recurso não encontrado.", content = @Content),
			@ApiResponse(responseCode = "405", description = "Método HTTP não permitido.", content = @Content),
			@ApiResponse(responseCode = "500", description = "Erro no servidor.", content = @Content) })
	@PostMapping(value = "/pfx/public-key/export", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<StreamingResponseBody> exportPublicKeyPfx(
			@RequestPart("pfxFile") @Parameter(description = "Arquivo .pfx") MultipartFile pfxFile,
			@RequestPart(name = "password") @Parameter(description = "Senha do arquivo pfx", required = true) String password) {
		var publicKey = pfxService.exportPublicKeyAsPem(pfxFile, password);

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
		return ResponseEntity.ok(pfxService.listAliases(pfxFile, password));
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