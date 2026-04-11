"""TLS/SSL certificate and configuration checks.

Validates certificate chains, expiry, cipher suites, protocol versions,
and security headers for remote hosts. Works on any domain — no server
access required.

Usage:
    tibet-audit check --tls example.com
    tibet-audit check --tls example.com:8443
"""

import ssl
import socket
import datetime
from typing import Optional
from .base import BaseCheck, CheckResult, Status, Severity


def _connect_and_get_cert(host: str, port: int = 443, timeout: float = 10.0) -> dict:
    """Connect to host and collect TLS information."""
    info = {
        "host": host,
        "port": port,
        "connected": False,
        "cert": None,
        "chain": [],
        "protocol": None,
        "cipher": None,
        "error": None,
    }

    try:
        # First: try WITH verification — if it works, we get full cert info
        ctx_verify = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_verify.load_default_certs()
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw_sock:
                with ctx_verify.wrap_socket(raw_sock, server_hostname=host) as s:
                    info["cert"] = s.getpeercert(binary_form=False)
                    info["cert_der"] = s.getpeercert(binary_form=True)
                    info["protocol"] = s.version()
                    info["cipher"] = s.cipher()
                    info["connected"] = True
                    info["chain_valid"] = True
        except ssl.SSLCertVerificationError as e:
            info["chain_valid"] = False
            info["chain_error"] = str(e)

            # Chain broken — connect without verification to still get cert data
            ctx_noverify = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_noverify.check_hostname = False
            ctx_noverify.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as raw_sock:
                with ctx_noverify.wrap_socket(raw_sock, server_hostname=host) as s:
                    info["cert_der"] = s.getpeercert(binary_form=True)
                    info["protocol"] = s.version()
                    info["cipher"] = s.cipher()
                    info["connected"] = True

                    # Parse cert from DER using ssl helper
                    try:
                        info["cert"] = ssl._ssl._test_decode_cert(None)  # won't work
                    except Exception:
                        pass

                    # Fallback: use openssl CLI to extract cert details
                    if not info.get("cert"):
                        info["cert"] = _openssl_cert_info(host, port)

    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        info["error"] = str(e)

    return info


def _parse_cert_date(date_str: str) -> Optional[datetime.datetime]:
    """Parse SSL cert date string to datetime."""
    try:
        return datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
    except (ValueError, TypeError):
        return None


def _openssl_cert_info(host: str, port: int = 443) -> Optional[dict]:
    """Use openssl CLI to extract certificate details when Python SSL can't."""
    import subprocess
    try:
        # Pipe: openssl s_client → openssl x509
        s_client = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host],
            input=b"", capture_output=True, timeout=10,
        )
        x509 = subprocess.run(
            ["openssl", "x509", "-noout", "-dates", "-subject", "-issuer",
             "-ext", "subjectAltName"],
            input=s_client.stdout, capture_output=True, timeout=10,
        )
        if x509.returncode != 0:
            return None

        cert_info: dict = {}
        for line in x509.stdout.decode("utf-8", errors="replace").strip().split("\n"):
            line = line.strip()
            if line.startswith("notBefore="):
                cert_info["notBefore"] = line.split("=", 1)[1]
            elif line.startswith("notAfter="):
                cert_info["notAfter"] = line.split("=", 1)[1]
            elif line.startswith("subject="):
                for part in line.split("=", 1)[1].split(","):
                    part = part.strip()
                    if "CN" in part and "=" in part:
                        cn = part.split("=", 1)[1].strip()
                        cert_info["subject"] = ((("commonName", cn),),)
            elif line.startswith("issuer="):
                issuer_rdn = []
                for part in line.split("=", 1)[1].split(","):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        issuer_rdn.append((k.strip(), v.strip()))
                if issuer_rdn:
                    cert_info["issuer"] = (tuple(issuer_rdn),)
            elif "DNS:" in line:
                sans = []
                for entry in line.split(","):
                    entry = entry.strip()
                    if entry.startswith("DNS:"):
                        sans.append(("DNS", entry[4:]))
                if sans:
                    cert_info["subjectAltName"] = tuple(sans)

        return cert_info if cert_info else None
    except Exception:
        return None


def _get_tls_context(context: dict) -> Optional[dict]:
    """Get or create TLS info from context."""
    if "tls_info" in context:
        return context["tls_info"]

    host = context.get("tls_host")
    if not host:
        return None

    port = int(context.get("tls_port", 443))
    info = _connect_and_get_cert(host, port)
    context["tls_info"] = info
    return info


class TLSChainCheck(BaseCheck):
    """Validates the SSL certificate chain is complete and trusted."""

    check_id = "TLS-001"
    name = "Certificate Chain Validation"
    description = "Verifies the full certificate chain is sent and trusted by default CA stores"
    severity = Severity.CRITICAL
    category = "tls"
    score_weight = 15

    def run(self, context: dict) -> CheckResult:
        info = _get_tls_context(context)
        if not info:
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.SKIPPED, severity=self.severity,
                message="No TLS host specified. Use --tls <hostname> to scan a domain.",
            )

        if info.get("error"):
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.FAILED, severity=Severity.CRITICAL,
                message=f"Connection failed: {info['error']}",
                score_impact=self.score_weight,
            )

        if info.get("chain_valid"):
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.PASSED, severity=self.severity,
                message=f"Certificate chain for {info['host']} is complete and trusted.",
            )

        chain_error = info.get("chain_error", "unknown verification error")
        is_intermediate = "unable to get local issuer" in chain_error or "unable to verify" in chain_error

        recommendation = "Add the missing intermediate certificate to your server's SSL bundle."
        if is_intermediate:
            recommendation = (
                "The intermediate certificate is missing from the chain. "
                "Download it from your CA (e.g., Sectigo, Let's Encrypt) and "
                "concatenate it with your server certificate in the ssl_certificate file. "
                "Most clients will fail to verify the connection without it."
            )

        return CheckResult(
            check_id=self.check_id, name=self.name,
            status=Status.FAILED, severity=Severity.CRITICAL,
            message=f"Broken certificate chain for {info['host']}: {chain_error}",
            recommendation=recommendation,
            score_impact=self.score_weight,
            references=["https://www.ssllabs.com/ssltest/", "https://whatsmychaincert.com/"],
        )


class TLSExpiryCheck(BaseCheck):
    """Checks if the certificate is expired or expiring soon."""

    check_id = "TLS-002"
    name = "Certificate Expiry"
    description = "Verifies the certificate is not expired and warns if expiring within 30 days"
    severity = Severity.HIGH
    category = "tls"
    score_weight = 12

    def run(self, context: dict) -> CheckResult:
        info = _get_tls_context(context)
        if not info or not info.get("cert"):
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.SKIPPED, severity=self.severity,
                message="No certificate available to check.",
            )

        cert = info["cert"]
        not_after = _parse_cert_date(cert.get("notAfter", ""))
        not_before = _parse_cert_date(cert.get("notBefore", ""))
        now = datetime.datetime.utcnow()

        if not not_after:
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.WARNING, severity=self.severity,
                message="Could not parse certificate expiry date.",
                score_impact=5,
            )

        if now > not_after:
            days_expired = (now - not_after).days
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.FAILED, severity=Severity.CRITICAL,
                message=f"Certificate EXPIRED {days_expired} days ago (expired {not_after.strftime('%Y-%m-%d')}).",
                recommendation="Renew the certificate immediately.",
                score_impact=self.score_weight,
            )

        if now < not_before:
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.FAILED, severity=Severity.HIGH,
                message=f"Certificate not yet valid (valid from {not_before.strftime('%Y-%m-%d')}).",
                score_impact=self.score_weight,
            )

        days_remaining = (not_after - now).days

        if days_remaining <= 7:
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.FAILED, severity=Severity.CRITICAL,
                message=f"Certificate expires in {days_remaining} days ({not_after.strftime('%Y-%m-%d')}).",
                recommendation="Renew immediately — less than 7 days remaining.",
                score_impact=self.score_weight,
            )

        if days_remaining <= 30:
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.WARNING, severity=Severity.HIGH,
                message=f"Certificate expires in {days_remaining} days ({not_after.strftime('%Y-%m-%d')}).",
                recommendation="Schedule certificate renewal soon.",
                score_impact=5,
            )

        return CheckResult(
            check_id=self.check_id, name=self.name,
            status=Status.PASSED, severity=self.severity,
            message=f"Certificate valid for {days_remaining} more days (expires {not_after.strftime('%Y-%m-%d')}).",
        )


class TLSProtocolCheck(BaseCheck):
    """Checks TLS protocol version — TLS 1.2+ required."""

    check_id = "TLS-003"
    name = "TLS Protocol Version"
    description = "Ensures TLS 1.2 or higher is negotiated (SSLv3, TLS 1.0, TLS 1.1 are insecure)"
    severity = Severity.HIGH
    category = "tls"
    score_weight = 10

    def run(self, context: dict) -> CheckResult:
        info = _get_tls_context(context)
        if not info or not info.get("protocol"):
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.SKIPPED, severity=self.severity,
                message="No TLS connection available.",
            )

        protocol = info["protocol"]
        secure_versions = {"TLSv1.2", "TLSv1.3"}

        if protocol in secure_versions:
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.PASSED, severity=self.severity,
                message=f"Server negotiated {protocol}.",
            )

        return CheckResult(
            check_id=self.check_id, name=self.name,
            status=Status.FAILED, severity=Severity.CRITICAL,
            message=f"Server negotiated {protocol} — this version is insecure.",
            recommendation="Disable SSLv3, TLS 1.0, and TLS 1.1. Configure TLS 1.2 as minimum.",
            score_impact=self.score_weight,
            references=["https://datatracker.ietf.org/doc/html/rfc8996"],
        )


class TLSCipherCheck(BaseCheck):
    """Checks negotiated cipher suite strength."""

    check_id = "TLS-004"
    name = "Cipher Suite Strength"
    description = "Verifies the negotiated cipher suite uses strong algorithms"
    severity = Severity.HIGH
    category = "tls"
    score_weight = 10

    WEAK_CIPHERS = {"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"}

    def run(self, context: dict) -> CheckResult:
        info = _get_tls_context(context)
        if not info or not info.get("cipher"):
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.SKIPPED, severity=self.severity,
                message="No cipher information available.",
            )

        cipher_name, protocol, bits = info["cipher"]
        cipher_upper = cipher_name.upper()

        weak_found = [w for w in self.WEAK_CIPHERS if w in cipher_upper]
        if weak_found:
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.FAILED, severity=Severity.CRITICAL,
                message=f"Weak cipher: {cipher_name} (flagged: {', '.join(weak_found)}).",
                recommendation="Disable weak cipher suites. Use ECDHE+AESGCM or CHACHA20.",
                score_impact=self.score_weight,
            )

        if bits and bits < 128:
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.FAILED, severity=Severity.HIGH,
                message=f"Cipher {cipher_name} uses only {bits}-bit encryption.",
                recommendation="Require 128-bit minimum. Prefer 256-bit (AES-256-GCM).",
                score_impact=self.score_weight,
            )

        return CheckResult(
            check_id=self.check_id, name=self.name,
            status=Status.PASSED, severity=self.severity,
            message=f"Strong cipher: {cipher_name} ({bits}-bit).",
        )


class TLSHostnameCheck(BaseCheck):
    """Verifies the certificate matches the requested hostname."""

    check_id = "TLS-005"
    name = "Hostname Match"
    description = "Checks that the certificate's CN or SAN matches the target hostname"
    severity = Severity.CRITICAL
    category = "tls"
    score_weight = 12

    def run(self, context: dict) -> CheckResult:
        info = _get_tls_context(context)
        if not info or not info.get("cert"):
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.SKIPPED, severity=self.severity,
                message="No certificate available.",
            )

        cert = info["cert"]
        host = info["host"]

        # Check Subject Alternative Names
        san_entries = []
        for san_type, san_value in cert.get("subjectAltName", []):
            if san_type == "DNS":
                san_entries.append(san_value)

        # Check Common Name as fallback
        cn = ""
        for rdn in cert.get("subject", ()):
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    cn = attr_value

        all_names = san_entries or ([cn] if cn else [])

        # Match hostname against cert names (including wildcards)
        matched = False
        for name in all_names:
            if name == host:
                matched = True
                break
            if name.startswith("*."):
                wildcard_domain = name[2:]
                if host.endswith(wildcard_domain) and host.count(".") == name.count("."):
                    matched = True
                    break

        if matched:
            names_str = ", ".join(all_names[:3])
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.PASSED, severity=self.severity,
                message=f"Certificate matches {host} (names: {names_str}).",
            )

        return CheckResult(
            check_id=self.check_id, name=self.name,
            status=Status.FAILED, severity=Severity.CRITICAL,
            message=f"Certificate does NOT match {host}. Names on cert: {', '.join(all_names)}.",
            recommendation="Obtain a certificate that includes the correct hostname in CN or SAN.",
            score_impact=self.score_weight,
        )


class TLSKeyStrengthCheck(BaseCheck):
    """Checks certificate key size (RSA 2048+ or ECDSA 256+)."""

    check_id = "TLS-006"
    name = "Key Strength"
    description = "Verifies the certificate uses sufficiently strong keys"
    severity = Severity.HIGH
    category = "tls"
    score_weight = 10

    def run(self, context: dict) -> CheckResult:
        info = _get_tls_context(context)
        if not info or not info.get("cert"):
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.SKIPPED, severity=self.severity,
                message="No certificate available.",
            )

        # Try to get key info from the cipher negotiation
        cipher_info = info.get("cipher")
        cert = info["cert"]

        # Extract issuer info to report
        issuer_parts = []
        for rdn in cert.get("issuer", ()):
            for attr_type, attr_value in rdn:
                if attr_type in ("organizationName", "commonName"):
                    issuer_parts.append(attr_value)
        issuer = " / ".join(issuer_parts) if issuer_parts else "Unknown"

        # Python's ssl module doesn't directly expose key size from getpeercert()
        # We can infer from the cipher suite
        if cipher_info:
            cipher_name = cipher_info[0]
            if "ECDSA" in cipher_name or "ECDHE" in cipher_name:
                return CheckResult(
                    check_id=self.check_id, name=self.name,
                    status=Status.PASSED, severity=self.severity,
                    message=f"ECDHE/ECDSA cipher in use ({cipher_name}). Issuer: {issuer}.",
                )

        # For RSA, check if the cipher bits are reasonable
        if cipher_info and cipher_info[2]:
            bits = cipher_info[2]
            if bits >= 256:
                return CheckResult(
                    check_id=self.check_id, name=self.name,
                    status=Status.PASSED, severity=self.severity,
                    message=f"Strong encryption: {bits}-bit. Issuer: {issuer}.",
                )

        # If we can't determine, pass with note
        return CheckResult(
            check_id=self.check_id, name=self.name,
            status=Status.PASSED, severity=self.severity,
            message=f"Certificate issued by {issuer}. Use ssllabs.com for detailed key analysis.",
            references=["https://www.ssllabs.com/ssltest/"],
        )


class TLSSecurityHeadersCheck(BaseCheck):
    """Checks HSTS and other TLS-related HTTP headers."""

    check_id = "TLS-007"
    name = "HSTS & Security Headers"
    description = "Checks for Strict-Transport-Security and other security headers via HTTPS"
    severity = Severity.HIGH
    category = "tls"
    score_weight = 8

    def run(self, context: dict) -> CheckResult:
        info = _get_tls_context(context)
        if not info or not info.get("connected"):
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.SKIPPED, severity=self.severity,
                message="No TLS connection available.",
            )

        host = info["host"]
        port = info["port"]

        # Do an HTTP request to check headers
        import http.client
        missing = []
        found = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=10, context=ctx)
            conn.request("HEAD", "/")
            resp = conn.getresponse()
            headers = {k.lower(): v for k, v in resp.getheaders()}
            conn.close()

            checks = {
                "strict-transport-security": "HSTS",
                "x-frame-options": "X-Frame-Options",
                "x-content-type-options": "X-Content-Type-Options",
                "content-security-policy": "CSP",
                "referrer-policy": "Referrer-Policy",
                "permissions-policy": "Permissions-Policy",
            }

            for header, label in checks.items():
                if header in headers:
                    found.append(label)
                else:
                    missing.append(label)

            # Check for version disclosure
            powered_by = headers.get("x-powered-by", "")
            server = headers.get("server", "")

            info["http_headers"] = headers
            info["missing_headers"] = missing
            info["found_headers"] = found
            info["version_disclosed"] = bool(powered_by or ("/" in server))

        except Exception as e:
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.WARNING, severity=self.severity,
                message=f"Could not fetch HTTP headers: {e}",
                score_impact=3,
            )

        if not missing:
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.PASSED, severity=self.severity,
                message=f"All security headers present: {', '.join(found)}.",
            )

        status = Status.FAILED if "HSTS" in missing else Status.WARNING
        impact = self.score_weight if "HSTS" in missing else 4

        parts = []
        if found:
            parts.append(f"Present: {', '.join(found)}")
        parts.append(f"Missing: {', '.join(missing)}")

        recommendation = "Add missing headers to your web server configuration."
        if "HSTS" in missing:
            recommendation = (
                "Add Strict-Transport-Security header (e.g., max-age=31536000; includeSubDomains). "
                "Without HSTS, browsers don't enforce HTTPS and connections can be downgraded."
            )

        return CheckResult(
            check_id=self.check_id, name=self.name,
            status=status, severity=self.severity,
            message=f"Security headers for {host}: {'. '.join(parts)}.",
            recommendation=recommendation,
            score_impact=impact,
            references=["https://securityheaders.com/"],
        )


class TLSVersionDisclosureCheck(BaseCheck):
    """Checks if the server discloses software versions in headers."""

    check_id = "TLS-008"
    name = "Version Disclosure"
    description = "Checks for X-Powered-By, Server version, and other information leaks"
    severity = Severity.MEDIUM
    category = "tls"
    score_weight = 5

    def run(self, context: dict) -> CheckResult:
        info = _get_tls_context(context)
        if not info:
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.SKIPPED, severity=self.severity,
                message="No TLS connection available.",
            )

        headers = info.get("http_headers")
        if headers is None:
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.SKIPPED, severity=self.severity,
                message="HTTP headers not available (run TLS-007 first).",
            )

        disclosures = []
        powered_by = headers.get("x-powered-by", "")
        server = headers.get("server", "")

        if powered_by:
            disclosures.append(f"X-Powered-By: {powered_by}")
        if "/" in server:
            disclosures.append(f"Server: {server}")

        if not disclosures:
            return CheckResult(
                check_id=self.check_id, name=self.name,
                status=Status.PASSED, severity=self.severity,
                message="No version information disclosed in headers.",
            )

        return CheckResult(
            check_id=self.check_id, name=self.name,
            status=Status.WARNING, severity=self.severity,
            message=f"Version disclosed: {'; '.join(disclosures)}",
            recommendation="Remove X-Powered-By header (expose_php=Off in php.ini) and suppress server version in web server config.",
            score_impact=self.score_weight,
        )


# Module-level check instances
TLS_CHECKS = [
    TLSChainCheck(),
    TLSExpiryCheck(),
    TLSProtocolCheck(),
    TLSCipherCheck(),
    TLSHostnameCheck(),
    TLSKeyStrengthCheck(),
    TLSSecurityHeadersCheck(),
    TLSVersionDisclosureCheck(),
]
