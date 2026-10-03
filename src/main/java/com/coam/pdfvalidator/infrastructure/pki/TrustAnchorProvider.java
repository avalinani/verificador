package com.coam.pdfvalidator.infrastructure.pki;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.port.TrustedCertificateSource;
import com.coam.pdfvalidator.infrastructure.bouncycastle.X509CertificateInfoMapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Loads X.509 certificates as {@link TrustAnchor}s for {@link
 * PkixCertificateChainValidator}, from up to three sources: the bundled
 * anchors on the classpath (the files listed in {@code truststore/index.txt},
 * generated from the EU trusted lists and documented with their provenance
 * in {@code truststore/SOURCES.md}), an optional external
 * directory of certificate files (one certificate per file; PEM or DER), and
 * an optional PKCS#12 keystore file. All three are additive: every source
 * that is configured contributes its certificates to the same trust anchor
 * set.
 *
 * <p><b>An anchor need not be a self-signed root</b>: the EU Trusted Lists
 * model (eIDAS) publishes the qualified ISSUING CA (and the TSA unit) as the
 * trusted service, which is usually not a self-signed root. {@link
 * PkixCertificateChainValidator} supports this (a non-self-signed anchor
 * still resolves to {@code TRUSTED} via the JDK's own PKIX path builder;
 * verified by {@code PkixCertificateChainValidatorTest}).
 *
 * <p>Spring configuration-property wiring for the external directory/PKCS#12
 * path is planned for T09; for now both are plain constructor parameters, so
 * whoever assembles a {@link PkixCertificateChainValidator} (a test, or a
 * future {@code @Configuration} class) passes them directly.
 */
public final class TrustAnchorProvider implements TrustedCertificateSource {

    private static final System.Logger LOGGER = System.getLogger(TrustAnchorProvider.class.getName());

    /**
     * The list of bundled anchor files under the classpath {@code truststore/}
     * folder, one file name per line ({@code #} starts a comment). Read
     * instead of scanning the folder because classpath directory listing
     * behaves differently between an exploded classes directory and a
     * packaged jar. The folder, this index and {@code SOURCES.md} are
     * generated together from the EU trusted lists by the maintainer tool
     * {@code com.coam.pdfvalidator.tools.tsl.TslSync} (T14).
     */
    static final String BUNDLED_INDEX = "truststore/index.txt";

    private static final Pattern SAFE_FILE_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]*");

    private final Set<TrustAnchor> trustAnchors;

    private TrustAnchorProvider(Set<TrustAnchor> trustAnchors) {
        this.trustAnchors = Set.copyOf(trustAnchors);
    }

    /** Test/DI convenience: build a provider directly from explicit root certificates, no I/O involved. */
    public static TrustAnchorProvider of(X509Certificate... roots) {
        Set<TrustAnchor> anchors = new HashSet<>();
        for (X509Certificate root : roots) {
            anchors.add(new TrustAnchor(root, null));
        }
        return new TrustAnchorProvider(anchors);
    }

    /** Loads only the bundled classpath roots (no external directory or PKCS#12 file). */
    public static TrustAnchorProvider bundled() throws IOException, GeneralSecurityException {
        return load(null, null, null);
    }

    /**
     * Loads the bundled classpath roots, plus (when non-{@code null}) every
     * certificate file in {@code externalDirectory} and/or every certificate
     * entry in the PKCS#12 keystore at {@code pkcs12File}.
     *
     * @param externalDirectory a directory containing one certificate
     *                          (PEM or DER) per file, or {@code null} to skip it
     * @param pkcs12File        a PKCS#12 keystore file, or {@code null} to skip it
     * @param pkcs12Password    the PKCS#12 keystore password (ignored when
     *                          {@code pkcs12File} is {@code null})
     */
    public static TrustAnchorProvider load(Path externalDirectory, Path pkcs12File, char[] pkcs12Password)
            throws IOException, GeneralSecurityException {
        List<X509Certificate> certificates = new ArrayList<>(loadBundledRoots());
        if (externalDirectory != null) {
            certificates.addAll(loadDirectory(externalDirectory));
        }
        if (pkcs12File != null) {
            certificates.addAll(loadPkcs12(pkcs12File, pkcs12Password));
        }

        Set<TrustAnchor> anchors = new HashSet<>();
        for (X509Certificate certificate : certificates) {
            anchors.add(new TrustAnchor(certificate, null));
        }
        return new TrustAnchorProvider(anchors);
    }

    public Set<TrustAnchor> trustAnchors() {
        return trustAnchors;
    }

    /** The anchor certificates mapped to the domain type, for adapters that look a certificate up by identity. */
    @Override
    public List<CertificateInfo> trustedCertificates() {
        List<CertificateInfo> certificates = new ArrayList<>();
        for (TrustAnchor anchor : trustAnchors) {
            X509Certificate certificate = anchor.getTrustedCert();
            if (certificate != null) {
                try {
                    certificates.add(X509CertificateInfoMapper.toDomain(certificate));
                } catch (RuntimeException e) {
                    LOGGER.log(System.Logger.Level.WARNING, "A trust anchor could not be mapped for lookup", e);
                }
            }
        }
        return certificates;
    }

    public int size() {
        return trustAnchors.size();
    }

    private static List<String> bundledAnchorResources() throws IOException {
        try (InputStream in = TrustAnchorProvider.class.getClassLoader().getResourceAsStream(BUNDLED_INDEX)) {
            if (in == null) {
                throw new IOException("Bundled trust anchor index not found on the classpath: " + BUNDLED_INDEX);
            }
            return parseIndex(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    /**
     * Parses the content of the bundled index into classpath resource names, in order. Blank lines
     * and {@code #} comments are skipped; an index that lists nothing is rejected, because the
     * service would otherwise start with zero bundled anchors and report every signature as
     * untrusted.
     */
    static List<String> parseIndex(String content) throws IOException {
        List<String> resources = new ArrayList<>();
        for (String line : content.split("\\R")) {
            String fileName = line.strip();
            if (fileName.isEmpty() || fileName.startsWith("#")) {
                continue;
            }
            if (!SAFE_FILE_NAME.matcher(fileName).matches()) {
                throw new IOException("Invalid entry in " + BUNDLED_INDEX + ": " + fileName);
            }
            resources.add("truststore/" + fileName);
        }
        if (resources.isEmpty()) {
            throw new IOException("Bundled trust anchor index lists no trust anchors: " + BUNDLED_INDEX);
        }
        return resources;
    }

    private static List<X509Certificate> loadBundledRoots() throws IOException, GeneralSecurityException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<String> resources = bundledAnchorResources();
        List<X509Certificate> certificates = new ArrayList<>(resources.size());
        for (String resource : resources) {
            try (InputStream in = TrustAnchorProvider.class.getClassLoader().getResourceAsStream(resource)) {
                if (in == null) {
                    throw new IOException("Bundled trust anchor resource not found on the classpath: " + resource);
                }
                certificates.add((X509Certificate) factory.generateCertificate(in));
            }
        }
        return certificates;
    }

    /**
     * Loads every certificate file in {@code directory}. A file that is not
     * a valid PEM/DER certificate (or otherwise unreadable) is skipped --
     * logged, never allowed to abort loading the rest of the external
     * directory or the trust store as a whole -- matching the "a single bad
     * input never aborts the whole analysis" convention used throughout this
     * codebase's other adapters (e.g. {@code BcSignatureVerifier} per
     * signature field, {@code PkixCertificateChainValidator} per
     * certificate).
     *
     * <p><b>T07b</b>: the directory itself being unreadable (missing,
     * permission denied, or any other {@link IOException} from opening the
     * directory stream) is handled the same way: reported/logged and
     * treated as "no certificates from this source" rather than propagated,
     * since one misconfigured external directory should not abort loading
     * the bundled roots that are always available.
     */
    private static List<X509Certificate> loadDirectory(Path directory) {
        CertificateFactory factory;
        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            // "X.509" is always available on any conformant JVM; this is
            // unreachable in practice, but never let it escape as anything
            // other than "no certificates from this source" either.
            LOGGER.log(System.Logger.Level.WARNING, () -> "X.509 CertificateFactory unavailable: " + e.getMessage());
            return List.of();
        }
        List<X509Certificate> certificates = new ArrayList<>();
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
            for (Path entry : entries) {
                if (Files.isRegularFile(entry)) {
                    try (InputStream in = Files.newInputStream(entry)) {
                        certificates.add((X509Certificate) factory.generateCertificate(in));
                    } catch (IOException | CertificateException e) {
                        LOGGER.log(System.Logger.Level.WARNING,
                                () -> "Skipping unreadable trust anchor file " + entry + ": " + e.getMessage());
                    }
                }
            }
        } catch (IOException e) {
            LOGGER.log(System.Logger.Level.WARNING,
                    () -> "Skipping unreadable external trust anchor directory " + directory + ": " + e.getMessage());
        }
        return certificates;
    }

    private static List<X509Certificate> loadPkcs12(Path pkcs12File, char[] password)
            throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(pkcs12File)) {
            keyStore.load(in, password);
        }
        List<X509Certificate> certificates = new ArrayList<>();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate certificate = keyStore.getCertificate(alias);
            if (certificate instanceof X509Certificate x509Certificate) {
                certificates.add(x509Certificate);
            }
        }
        return certificates;
    }
}
