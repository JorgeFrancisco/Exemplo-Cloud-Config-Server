package com.example.cloudconfigpropserver.service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import com.example.cloudconfigpropserver.exception.CertificateGenerationException;
import com.example.cloudconfigpropserver.model.AppFile;

@Service
public class CertificateService {

	private static final String RSA = "RSA";

	private static final String SHA512_WITH_RSA = "SHA512WithRSA";

	private static final String PKCS12 = "PKCS12";

	private static final String DOMAIN = "*.jfbm.tech.br";

	private static final String PROJECT = "Examples";

	private static final String ORGANIZATION = "JFBM";

	private static final String IP = "127.0.0.1";

	private static final String DNS = "jfbm.tech.br";

	private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();

	private static final SecureRandom PRNG = new SecureRandom();

	public AppFile createCertificate(String aliasName, String fileName, String password)
			throws CertificateGenerationException {
		try {
			Security.insertProviderAt(BC_PROVIDER, 1);

			final var keyPair = generateKeyPair(RSA, 4096);

			final var x500subject = buildSubjectName();

			final var x509Cert = generateSelfSignedCertificate(keyPair, x500subject, Validity.ofYears(50),
					SHA512_WITH_RSA);

			return createKeyStoreFile(keyPair, password.toCharArray(), aliasName, x509Cert, fileName);
		} catch (NoSuchAlgorithmException | OperatorCreationException | CertificateException | KeyStoreException
				| IOException e) {
			throw new CertificateGenerationException("Erro ao gerar certificado", e);
		}
	}

	private static AppFile createKeyStoreFile(final KeyPair keyPair, final char[] pwChars, final String aliasName,
			final X509Certificate x509Cert, final String fileName)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		final var keystore = KeyStore.getInstance(PKCS12);

		keystore.load(null, null);

		keystore.setKeyEntry(aliasName, keyPair.getPrivate(), pwChars, new X509Certificate[] { x509Cert });

		byte[] outputStream;

		try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
			keystore.store(byteArrayOutputStream, pwChars);

			outputStream = byteArrayOutputStream.toByteArray();
		}

		return new AppFile(fileName, outputStream);
	}

	private static KeyPair generateKeyPair(final String algorithm, final int keysize) throws NoSuchAlgorithmException {
		final var keyPairGenerator = KeyPairGenerator.getInstance(algorithm, BC_PROVIDER);

		keyPairGenerator.initialize(keysize, PRNG);

		return keyPairGenerator.generateKeyPair();
	}

	private static X500Name buildSubjectName() {
		return new X500Name(new RDN[] {
				new RDN(new AttributeTypeAndValue[] { new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String(DOMAIN)),
						new AttributeTypeAndValue(BCStyle.OU, new DERUTF8String(PROJECT)),
						new AttributeTypeAndValue(BCStyle.O, new DERUTF8String(ORGANIZATION)) }) });
	}

	private static X509Certificate generateSelfSignedCertificate(final KeyPair keyPair, final X500Name subject,
			final Validity validity, final String signatureAlgorithm)
			throws IOException, OperatorCreationException, CertificateException {
		final var sn = new BigInteger(128, PRNG);

		final var issuer = subject;

		final var keyPublic = keyPair.getPublic();
		final var keyPublicEncoded = keyPublic.getEncoded();
		final var keyPublicInfo = SubjectPublicKeyInfo.getInstance(keyPublicEncoded);

		try (final var ist = new ByteArrayInputStream(keyPublicEncoded); final var ais = new ASN1InputStream(ist)) {
			final var asn1Sequence = (ASN1Sequence) ais.readObject();

			final var subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(asn1Sequence);
			final var subjectPublicKeyId = new BcX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo);

			final var certBuilder = new X509v3CertificateBuilder(issuer, sn, validity.notBefore, validity.notAfter,
					subject, keyPublicInfo);

			final var contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

			final var generalNamesBuilder = new GeneralNamesBuilder().addName(new GeneralName(GeneralName.dNSName, DNS))
					.addName(new GeneralName(GeneralName.iPAddress, IP));

			final var certHolder = certBuilder.addExtension(Extension.subjectKeyIdentifier, false, subjectPublicKeyId)
					.addExtension(Extension.subjectAlternativeName, false,
							generalNamesBuilder.build().getEncoded(ASN1Encoding.DER))
					.build(contentSigner);

			return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(certHolder);
		}
	}

	private static final record Validity(Date notBefore, Date notAfter) {
		private static Validity ofYears(final int count) {
			final var zdtNotBefore = ZonedDateTime.now();

			final var zdtNotAfter = zdtNotBefore.plusYears(count);

			return of(zdtNotBefore.toInstant(), zdtNotAfter.toInstant());
		}

		private static Validity of(final Instant notBefore, final Instant notAfter) {
			return new Validity(Date.from(notBefore), Date.from(notAfter));
		}
	}
}