package com.example.cloudconfigpropserver.service;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import com.example.cloudconfigpropserver.model.AppFile;

@Service
public class UtilService {

	public Map<String, String> generatePasswordsByEnvironment() {
		return Stream.of("development", "staging", "production")
				.collect(Collectors.toMap(Function.identity(), e -> generateRandomAlphanumericString()));
	}

	private String generateRandomAlphanumericString() {
		final int leftLimit = 48; // '0'
		final int rightLimit = 122;
		final int targetStringLength = 15;

		return new SecureRandom().ints(leftLimit, rightLimit + 1)
				.filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97)) // alfanuméricos
				.limit(targetStringLength)
				.collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString();
	}

	public StreamingResponseBody generateZipFiles(List<AppFile> files) {
		return new StreamingResponseBody() {

			@Override
			public void writeTo(OutputStream outputStream) throws IOException {
				try (ZipOutputStream zos = new ZipOutputStream(outputStream)) {
					for (AppFile file : files) {
						ZipEntry entry = new ZipEntry(file.getName());

						zos.putNextEntry(entry);
						zos.write(file.getContent());
						zos.closeEntry();
					}

					zos.finish();
				}
			}
		};
	}
}