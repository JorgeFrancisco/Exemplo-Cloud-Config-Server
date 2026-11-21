package com.example.cloudconfigpropserver.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {

	@ExceptionHandler(InvalidFileException.class)
	public ResponseEntity<String> handleInvalidFile(InvalidFileException e) {
		return ResponseEntity.badRequest().body(e.getMessage());
	}
}
