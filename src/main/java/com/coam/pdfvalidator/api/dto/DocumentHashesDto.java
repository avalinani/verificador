package com.coam.pdfvalidator.api.dto;

/** SHA-256 and SHA-512 digests of the whole uploaded PDF file, as lowercase hex. */
public record DocumentHashesDto(String sha256, String sha512) {
}
