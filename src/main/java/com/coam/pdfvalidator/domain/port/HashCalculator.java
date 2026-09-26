package com.coam.pdfvalidator.domain.port;

import com.coam.pdfvalidator.domain.model.DocumentHashes;

/** Computes the digests of a whole PDF file. */
public interface HashCalculator {

    DocumentHashes hash(byte[] content);
}
