package com.coam.pdfvalidator.infrastructure.revocation;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RevocationUrlGuardTest {

    private static InetAddress ip(String literal) {
        try {
            return InetAddress.getByAddress(parseIpv4(literal));
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] parseIpv4(String literal) {
        String[] parts = literal.split("\\.");
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            bytes[i] = (byte) Integer.parseInt(parts[i]);
        }
        return bytes;
    }

    private static InetAddress ipv6(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    private static HostResolver fixedResolver(InetAddress... addresses) {
        return host -> addresses;
    }

    @Test
    void aPlainHttpUrlResolvingToAPublicAddressIsAccepted() {
        RevocationUrlGuard.ValidatedTarget target = RevocationUrlGuard.resolve(
                "http://ocsp.example.org/ee", false, fixedResolver(ip("93.184.216.34")));
        assertThat(target.uri().getHost()).isEqualTo("ocsp.example.org");
        assertThat(target.address()).isEqualTo(ip("93.184.216.34"));
    }

    @Test
    void anHttpsUrlIsRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "https://ocsp.example.org/ee", false, fixedResolver(ip("93.184.216.34"))))
                .isInstanceOf(RevocationUrlRejectedException.class)
                .hasMessageContaining("http");
    }

    @Test
    void aMalformedUrlIsRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://[not a url", false, fixedResolver(ip("93.184.216.34"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
    }

    @Test
    void aLoopbackAddressIsRejectedByDefault() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ip("127.0.0.1"))))
                .isInstanceOf(RevocationUrlRejectedException.class)
                .hasMessageContaining("private/loopback/reserved");
    }

    @Test
    void aLinkLocalCloudMetadataAddressIsRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://metadata.internal/ee", false, fixedResolver(ip("169.254.169.254"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
    }

    @Test
    void rfc1918PrivateAddressesAreRejected() {
        for (String literal : new String[] {"10.0.0.1", "172.16.0.1", "192.168.1.1"}) {
            assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                    "http://ocsp.internal/ee", false, fixedResolver(ip(literal))))
                    .as("literal %s", literal)
                    .isInstanceOf(RevocationUrlRejectedException.class);
        }
    }

    @Test
    void cgnatAddressesAreRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ip("100.64.0.1"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
        // 100.128.0.1 is outside the /10 (second octet > 127): must be treated as public.
        RevocationUrlGuard.ValidatedTarget target = RevocationUrlGuard.resolve(
                "http://ocsp.example.org/ee", false, fixedResolver(ip("100.128.0.1")));
        assertThat(target.address()).isEqualTo(ip("100.128.0.1"));
    }

    @Test
    void zeroSlashEightIsRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ip("0.0.0.5"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
    }

    @Test
    void multicastAddressesAreRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ip("224.0.0.1"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
    }

    @Test
    void ipv6UniqueLocalAddressesAreRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ipv6("fc00::1"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ipv6("fd12:3456::1"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
    }

    @Test
    void ipv4MappedIpv6PrivateAddressesAreRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ipv6("::ffff:10.0.0.1"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
    }

    @Test
    void ipv4MappedIpv6PublicAddressesAreAccepted() {
        RevocationUrlGuard.ValidatedTarget target = RevocationUrlGuard.resolve(
                "http://ocsp.example.org/ee", false, fixedResolver(ipv6("::ffff:93.184.216.34")));
        assertThat(target.address()).isEqualTo(ipv6("::ffff:93.184.216.34"));
    }

    @Test
    void privateAddressesAreAllowedWhenExplicitlyEnabledForTesting() {
        RevocationUrlGuard.ValidatedTarget target = RevocationUrlGuard.resolve(
                "http://127.0.0.1:8080/ee", true, fixedResolver(ip("127.0.0.1")));
        assertThat(target.address()).isEqualTo(ip("127.0.0.1"));
    }

    @Test
    void resolvesTheHostnameExactlyOnce() {
        AtomicInteger calls = new AtomicInteger();
        HostResolver resolver = host -> {
            calls.incrementAndGet();
            return new InetAddress[] {ip("93.184.216.34")};
        };
        RevocationUrlGuard.resolve("http://ocsp.example.org/ee", false, resolver);
        assertThat(calls.get()).isEqualTo(1);
    }

    /**
     * The core DNS-rebinding proof at the guard level: given several
     * candidate addresses from one single resolution, the guard must pick
     * the first <em>permitted</em> one from that same call -- it must never
     * call the resolver again (which a hostile authoritative DNS server
     * could answer differently the second time).
     */
    @Test
    void picksTheFirstPermittedAddressFromASingleResolutionWhenAPrivateAddressComesFirst() {
        RevocationUrlGuard.ValidatedTarget target = RevocationUrlGuard.resolve(
                "http://ocsp.example.org/ee", false,
                fixedResolver(ip("127.0.0.1"), ip("93.184.216.34")));
        assertThat(target.address()).isEqualTo(ip("93.184.216.34"));
    }

    @Test
    void aHostResolvingOnlyToPrivateAddressesIsRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ip("127.0.0.1"), ip("10.0.0.1"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
    }
}
