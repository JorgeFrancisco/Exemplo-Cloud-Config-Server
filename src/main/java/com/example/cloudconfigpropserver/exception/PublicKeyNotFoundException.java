package com.example.cloudconfigpropserver.exception;

/**
 * A chave publica da aplicacao nao foi encontrada no repositorio de properties. E devolvido
 * como 404 pelo {@link ApiExceptionHandler}.
 */
public class PublicKeyNotFoundException extends RuntimeException {

	private static final long serialVersionUID = -2381946518237709471L;

	public PublicKeyNotFoundException(String message, Throwable cause) {
		super(message, cause);
	}
}
