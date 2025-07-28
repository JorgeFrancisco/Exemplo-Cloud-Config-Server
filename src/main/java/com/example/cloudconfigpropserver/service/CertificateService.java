package com.example.cloudconfigpropserver.service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.Enumeration;

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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.example.cloudconfigpropserver.exception.CertificateGenerationException;
import com.example.cloudconfigpropserver.model.CertificateResult;
import com.example.cloudconfigpropserver.model.Constants;

@Service
public class CertificateService {

	private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();

	private static final SecureRandom PRNG = new SecureRandom();

	private final PfxService pfxService;

	@Autowired
	public CertificateService(PfxService pfxService) {
		this.pfxService = pfxService;
	}

	public CertificateResult createFiles(String alias, String password) throws CertificateGenerationException {
		try {
			Security.insertProviderAt(BC_PROVIDER, 1);

			final var keyPair = generateKeyPair(Constants.RSA, 2048);

			final var x500subject = buildSubjectName();

			final var x509Cert = generateSelfSignedCertificate(keyPair, x500subject, Validity.ofYears(50),
					Constants.SHA512_WITH_RSA);

			var pemFile = pfxService.exportPublicKeyAsPemToAppFile(keyPair.getPublic(), alias + Constants.PEM);

			var pfxFile = pfxService.createPfxFile(keyPair, password.toCharArray(), alias, x509Cert,
					alias + Constants.PFX);

			return new CertificateResult(pfxFile, pemFile);
		} catch (NoSuchAlgorithmException | OperatorCreationException | CertificateException | KeyStoreException
				| IOException e) {
			throw new CertificateGenerationException("Erro ao gerar os arquivos", e);
		}
	}

	public Enumeration<String> listAliases(MultipartFile pfxFile, String password) throws Exception {
		var keyStore = KeyStore.getInstance(Constants.PKCS12);

		try (InputStream inputStream = pfxFile.getInputStream()) {
			keyStore.load(inputStream, password.toCharArray());
		}

		return keyStore.aliases();
	}

	private KeyPair generateKeyPair(final String algorithm, final int keysize) throws NoSuchAlgorithmException {
		final var keyPairGenerator = KeyPairGenerator.getInstance(algorithm, BC_PROVIDER);

		keyPairGenerator.initialize(keysize, PRNG);

		return keyPairGenerator.generateKeyPair();
	}

	private static X500Name buildSubjectName() {
		return new X500Name(new RDN[] { new RDN(new AttributeTypeAndValue[] {
				new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String(Constants.DOMAIN)),
				new AttributeTypeAndValue(BCStyle.OU, new DERUTF8String(Constants.PROJECT)),
				new AttributeTypeAndValue(BCStyle.O, new DERUTF8String(Constants.ORGANIZATION)) }) });
	}

	private X509Certificate generateSelfSignedCertificate(final KeyPair keyPair, final X500Name subject,
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

			final var generalNamesBuilder = new GeneralNamesBuilder()
					.addName(new GeneralName(GeneralName.dNSName, Constants.DNS))
					.addName(new GeneralName(GeneralName.iPAddress, Constants.IP));

			final var certHolder = certBuilder.addExtension(Extension.subjectKeyIdentifier, false, subjectPublicKeyId)
					.addExtension(Extension.subjectAlternativeName, false,
							generalNamesBuilder.build().getEncoded(ASN1Encoding.DER))
					.build(contentSigner);

			return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(certHolder);
		}
	}

	private final record Validity(Date notBefore, Date notAfter) {

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