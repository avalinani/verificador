package com.coam.pdfvalidator.infrastructure.bouncycastle;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * Wraps a {@link DigestCalculatorProvider}, normalizing a SIGNATURE algorithm
 * OID used as a CMS {@code digestAlgorithm} (see {@link
 * DigestAlgorithmOidNormalizer}) to its actual digest OID before delegating --
 * so a non-standard, but real-world, {@code SignerInfo} encoding does not
 * fail with {@code NoSuchAlgorithmException}.
 */
final class NormalizingDigestCalculatorProvider implements DigestCalculatorProvider {

    private final DigestCalculatorProvider delegate;

    NormalizingDigestCalculatorProvider(DigestCalculatorProvider delegate) {
        this.delegate = delegate;
    }

    @Override
    public DigestCalculator get(AlgorithmIdentifier algorithmIdentifier) throws OperatorCreationException {
        return delegate.get(DigestAlgorithmOidNormalizer.normalize(algorithmIdentifier));
    }
}
