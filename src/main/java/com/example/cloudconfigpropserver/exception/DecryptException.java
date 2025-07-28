package com.example.cloudconfigpropserver.exception;

public class DecryptException extends RuntimeException {

	private static final long serialVersionUID = 3624754799133848023L;

	public DecryptException(String message, Throwable cause) {
		super(message, cause);
	}
}