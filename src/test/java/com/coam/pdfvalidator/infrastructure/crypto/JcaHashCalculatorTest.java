package com.coam.pdfvalidator.infrastructure.crypto;

import com.coam.pdfvalidator.domain.model.DocumentHashes;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies {@link JcaHashCalculator} against the well-known NIST test
 * vectors for SHA-256/SHA-512 (empty input and {@code "abc"}), rather than
 * merely checking internal consistency.
 */
class JcaHashCalculatorTest {

    private final JcaHashCalculator calculator = new JcaHashCalculator();

    @Test
    void hashesTheEmptyInput() {
        DocumentHashes hashes = calculator.hash(new byte[0]);

        assertThat(hashes.sha256())
                .isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assertThat(hashes.sha512())
                .isEqualTo("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }

    @Test
    void hashesAbc() {
        DocumentHashes hashes = calculator.hash("abc".getBytes(StandardCharsets.US_ASCII));

        assertThat(hashes.sha256()).isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assertThat(hashes.sha512())
                .isEqualTo("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    }

    @Test
    void hashesAreLowercaseHex() {
        DocumentHashes hashes = calculator.hash("abc".getBytes(StandardCharsets.US_ASCII));

        assertThat(hashes.sha256()).isLowerCase();
        assertThat(hashes.sha512()).isLowerCase();
    }
}
