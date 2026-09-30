package com.coam.pdfvalidator.domain.port;

import com.coam.pdfvalidator.domain.model.ChainStatus;
import com.coam.pdfvalidator.domain.model.RevocationStatus;
import com.coam.pdfvalidator.domain.model.SignatureExtraction;
import com.coam.pdfvalidator.domain.model.SignatureReport;

import java.util.List;

/**
 * Extracts every signature dictionary from a PDF and cryptographically
 * verifies it: {@code /ByteRange} shape, CMS/CAdES integrity, whether the
 * document was modified after signing, embedded timestamp, and the raw
 * certificate chain.
 *
 * <p><b>Design choice</b>: chain trust and revocation are cross-cutting
 * concerns the use case owns (they need a configured trust store and an
 * optional network call), not something a signature verifier should decide.
 * Rather than introducing a separate {@code ExtractedSignature} type to
 * carry the not-yet-enriched result, this port returns the very same
 * {@link SignatureReport} the use case will hand out, with
 * {@link ChainStatus#NOT_CHECKED} and {@link RevocationStatus#notChecked()}
 * as placeholders and {@code chain} already populated from the CMS
 * signer-info. The use case then calls {@code CertificateChainValidator} and
 * (optionally) {@code RevocationChecker} on that chain and produces the
 * final report via {@link SignatureReport#withChainAndRevocation}. This
 * keeps a single report type end-to-end instead of two near-identical
 * records, at the (acceptable) cost of the verifier constructing enum
 * placeholders it does not itself evaluate.
 */
public interface SignatureVerifier {

    List<SignatureReport> verify(byte[] pdf);

    /**
     * Like {@link #verify} but also says how many signature fields were left unanalysed because of a resource cap
     * (T20). The default suits verifiers that analyse everything.
     */
    default SignatureExtraction extract(byte[] pdf) {
        return new SignatureExtraction(verify(pdf), 0);
    }
}
