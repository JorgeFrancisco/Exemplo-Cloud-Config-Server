package com.example.cloudconfigpropserver.model;

import java.util.Date;

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
public class Alias {

	@Schema(description = "Nome do alias")
	@JsonProperty("name")
	private String name;

	@Schema(description = "Subject do certificado")
	@JsonProperty("subject")
	private String subject;

	@Schema(description = "Data inicial da validade do certificado")
	@JsonProperty("fromDate")
	private Date fromDate;

	@Schema(description = "Data final da validade do certificado")
	@JsonProperty("toDate")
	private Date toDate;

	@Schema(description = "Algoritmo do certificado")
	@JsonProperty("algorithm")
	private String algorithm;
}