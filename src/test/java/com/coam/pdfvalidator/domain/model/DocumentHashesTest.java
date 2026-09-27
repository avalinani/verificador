package com.coam.pdfvalidator.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class DocumentHashesTest {

    private static final String VALID_SHA256 = "a".repeat(64);
    private static final String VALID_SHA512 = "b".repeat(128);

    @Test
    void acceptsLowercaseHexOfTheExactExpectedLength() {
        assertThatNoException().isThrownBy(() -> new DocumentHashes(VALID_SHA256, VALID_SHA512));
    }

    @Test
    void rejectsASha256ThatIsTheWrongLength() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new DocumentHashes("a".repeat(63), VALID_SHA512));
    }

    @Test
    void rejectsASha512ThatIsTheWrongLength() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new DocumentHashes(VALID_SHA256, "b".repeat(127)));
    }

    @Test
    void rejectsUppercaseHexCharacters() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new DocumentHashes("A".repeat(64), VALID_SHA512));
    }

    @Test
    void rejectsNonHexCharacters() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new DocumentHashes("g".repeat(64), VALID_SHA512));
    }

    @Test
    void rejectsNullHashes() {
        assertThatNullPointerException().isThrownBy(() -> new DocumentHashes(null, VALID_SHA512));
        assertThatNullPointerException().isThrownBy(() -> new DocumentHashes(VALID_SHA256, null));
    }
}
