package com.coam.pdfvalidator.infrastructure.revocation;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * SSRF guard for OCSP/CRL distribution point URLs extracted from a
 * certificate's AIA/CDP extensions: a hostile or misissued certificate
 * could point either at an internal service (e.g. {@code
 * http://169.254.169.254/} or {@code http://localhost:8080/actuator}), and
 * this server must never blindly follow it.
 *
 * <p><b>DNS-rebinding TOCTOU</b>: an earlier version of this guard validated
 * the hostname's resolved addresses, then let {@code java.net.http.HttpClient}
 * resolve the same hostname <em>again</em> at connect time -- a hostile
 * authoritative DNS server can legitimately answer those two lookups
 * differently (a public address for the check, a private one for the
 * actual connection), defeating the guard entirely. {@link #resolve} fixes
 * this by resolving the hostname <em>exactly once</em>, picking one
 * permitted address, and returning it bundled with the request URI as a
 * {@link ValidatedTarget}; {@link PinnedHttpClient} then connects a plain
 * socket to that exact {@link InetAddress}, never to the hostname again.
 *
 * <p>Only {@code http} URLs are accepted -- see {@link PinnedHttpClient}'s
 * Javadoc for why {@code https} is rejected outright rather than pinned.
 * Unless {@code allowPrivateAddresses} is {@code true} (test-only: a local
 * test HTTP server bound to {@code localhost}; production wiring always
 * passes {@code false}), every resolved candidate address is checked
 * against {@link #isPrivateOrReserved} and the first permitted one is used;
 * if none is permitted, the URL is rejected. Redirects are never followed
 * at all ({@link PinnedHttpClient} implements a minimal, non-redirecting
 * HTTP/1.1 client), so a redirect to a private address cannot bypass this
 * guard either.
 */
final class RevocationUrlGuard {

    private RevocationUrlGuard() {
    }

    /** A request URI together with the exact single resolved address {@link PinnedHttpClient} must connect to. */
    record ValidatedTarget(URI uri, InetAddress address) {
    }

    static ValidatedTarget resolve(String urlString, boolean allowPrivateAddresses, HostResolver resolver) {
        URI uri;
        try {
            uri = new URI(urlString);
        } catch (URISyntaxException e) {
            throw new RevocationUrlRejectedException("malformed URL");
        }

        String scheme = uri.getScheme();
        if (scheme == null || !scheme.equalsIgnoreCase("http")) {
            throw new RevocationUrlRejectedException(
                    "unsupported URL scheme (only http is supported for revocation checking)");
        }

        String host = uri.getHost();
        if (host == null) {
            throw new RevocationUrlRejectedException("URL has no host");
        }

        InetAddress[] addresses;
        try {
            addresses = resolver.resolve(host);
        } catch (UnknownHostException e) {
            throw new RevocationUrlRejectedException("host could not be resolved");
        }

        for (InetAddress candidate : addresses) {
            if (allowPrivateAddresses || !isPrivateOrReserved(candidate)) {
                return new ValidatedTarget(uri, candidate);
            }
        }
        throw new RevocationUrlRejectedException(
                "URL resolves only to private/loopback/reserved addresses, refusing to contact it");
    }

    /**
     * Covers loopback, wildcard/any-local, link-local (incl. the {@code
     * 169.254.169.254} cloud-metadata address), IPv4 RFC 1918 private
     * ranges, IPv6 unique-local ({@code fc00::/7}), IPv4 {@code 0.0.0.0/8},
     * CGNAT ({@code 100.64.0.0/10}), and multicast -- both directly and
     * through an IPv4-mapped IPv6 address (e.g. {@code ::ffff:10.0.0.1}),
     * which is normalized to its embedded IPv4 address first so it cannot
     * slip past the IPv4-specific checks above.
     */
    private static boolean isPrivateOrReserved(InetAddress address) {
        if (address instanceof Inet6Address v6 && isIpv4Mapped(v6)) {
            return isPrivateOrReserved(toIpv4(v6));
        }

        if (address.isLoopbackAddress() || address.isAnyLocalAddress()
                || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }

        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            int firstOctet = bytes[0] & 0xFF;
            int secondOctet = bytes[1] & 0xFF;
            if (firstOctet == 0) {
                return true; // 0.0.0.0/8
            }
            return firstOctet == 100 && secondOctet >= 64 && secondOctet <= 127; // 100.64.0.0/10 (CGNAT)
        }
        if (bytes.length == 16) {
            // Unique local addresses, fc00::/7: the top 7 bits of the first
            // byte are 1111110 (0xFC or 0xFD as the first byte).
            return (bytes[0] & 0xFE) == 0xFC;
        }
        return false;
    }

    private static boolean isIpv4Mapped(Inet6Address address) {
        byte[] bytes = address.getAddress();
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return (bytes[10] & 0xFF) == 0xFF && (bytes[11] & 0xFF) == 0xFF;
    }

    private static InetAddress toIpv4(Inet6Address address) {
        byte[] bytes = address.getAddress();
        try {
            return InetAddress.getByAddress(Arrays.copyOfRange(bytes, 12, 16));
        } catch (UnknownHostException e) {
            // Unreachable: a 4-byte address is always a valid raw address.
            throw new IllegalStateException(e);
        }
    }
}
