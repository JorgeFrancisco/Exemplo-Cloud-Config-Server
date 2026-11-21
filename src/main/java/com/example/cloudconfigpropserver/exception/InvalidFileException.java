package com.example.cloudconfigpropserver.exception;

/**
 * Erro causado pelo arquivo ou pelos dados enviados na requisicao (arquivo invalido, senha
 * incorreta etc.). E devolvido como 400 pelo {@link ApiExceptionHandler}.
 */
public class InvalidFileException extends RuntimeException {

	private static final long serialVersionUID = 4593150278611984652L;

	public InvalidFileException(String message) {
		super(message);
	}

	public InvalidFileException(String message, Throwable cause) {
		super(message, cause);
	}
}
