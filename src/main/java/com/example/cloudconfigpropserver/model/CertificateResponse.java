package com.example.cloudconfigpropserver.model;

import java.util.List;

import org.springframework.http.HttpStatus;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Builder
public class CertificateResponse {

	@Schema(description = "Alias")
	@JsonProperty("alias")
	private Alias alias;

	@Schema(description = "Http status code")
	@JsonProperty("statusCode")
	private HttpStatus statusCode;

	@Schema(description = "Lista de erros, se houverem")
	@JsonProperty("errors")
	private List<String> errors;
}