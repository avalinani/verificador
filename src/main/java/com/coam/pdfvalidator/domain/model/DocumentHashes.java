package com.coam.pdfvalidator.domain.model;

import java.util.Objects;
import java.util.regex.Pattern;

/** SHA-256 and SHA-512 digests of a whole PDF file, as lowercase hex. */
public record DocumentHashes(String sha256, String sha512) {

    private static final Pattern SHA256_HEX = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern SHA512_HEX = Pattern.compile("[0-9a-f]{128}");

    public DocumentHashes {
        Objects.requireNonNull(sha256, "sha256");
        Objects.requireNonNull(sha512, "sha512");
        if (!SHA256_HEX.matcher(sha256).matches()) {
            throw new IllegalArgumentException("sha256 must be 64 lowercase hex characters, got: " + sha256);
        }
        if (!SHA512_HEX.matcher(sha512).matches()) {
            throw new IllegalArgumentException("sha512 must be 128 lowercase hex characters, got: " + sha512);
        }
    }
}
