package com.example.cloudconfigpropserver.config.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigurationTests {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void deveBloquearDecryptDoConfigServer() throws Exception {
		mockMvc.perform(post("/config/decrypt").content("{cipher}abc")).andExpect(status().isForbidden());
	}

	@Test
	void deveBloquearEndpointNaoLiberado() throws Exception {
		mockMvc.perform(get("/qualquer-coisa")).andExpect(status().isForbidden());
	}

	@Test
	void deveLiberarSwagger() throws Exception {
		mockMvc.perform(get("/v3/api-docs/swagger-config")).andExpect(status().isOk());
	}

	@Test
	void deveDesligarFiltroXssLegadoDoNavegador() throws Exception {
		mockMvc.perform(get("/v3/api-docs/swagger-config")).andExpect(header().string("X-XSS-Protection", "0"));
	}

	@Test
	void deveAceitarPreflightCorsDeOutraOrigem() throws Exception {
		mockMvc.perform(options("/certificate").header(HttpHeaders.ORIGIN, "http://outra-origem.com")
				.header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*"));
	}
}
