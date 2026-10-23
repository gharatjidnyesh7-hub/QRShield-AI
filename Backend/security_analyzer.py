"""
QRShield AI - Website Security & Redirect Analyzer (SSRF-hardened)
===================================================================
Inspects a submitted URL from the SERVER side without ever fetching page
content. Only response HEADERS are read; bodies are never downloaded.

SSRF protections
  * only http / https; credentials in the URL are stripped
  * only ports 80 and 443 (configurable via constructor)
  * hostname is resolved ONCE per hop; every returned address must be a
    global (public) unicast address -- loopback, private, link-local,
    multicast, reserved, unspecified, CGNAT, IPv4-mapped IPv6 and similar are
    rejected. If ANY resolved address is non-public the hop is refused.
  * the TCP connection is made to the validated IP literal itself (the
    hostname is never resolved a second time), which defeats DNS rebinding.
    TLS SNI / certificate checking and the Host header still use the hostname.
  * every redirect target is fully re-validated (scheme, port, DNS, IP)
  * max redirects, per-hop timeout, total deadline, header-size cap
  * TLS verification is NEVER disabled; an invalid certificate stops the
    analysis of that hop and is reported as a failed check
  * internal addresses are never returned to the caller; blocked hops are
    reported only as "non-public destination (blocked)".
"""

import http.client
import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit, urljoin, urlunsplit

from feature_extraction import SHORTENER_DOMAINS, IP_REGEX

PASSED, WARNING, FAILED, UNAVAILABLE = "Passed", "Warning", "Failed", "Unavailable"

MAX_URL_LENGTH = 2048
MAX_HEADER_BYTES = 32 * 1024
USER_AGENT = "QRShield-AI-Analyzer/1.0 (+headers-only link safety check)"

# Small built-in list so "same site?" comparisons handle common multi-part
# suffixes without a Public Suffix List dependency. Approximation; documented.
_MULTI_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
                   "co.in", "net.in", "org.in", "gov.in", "ac.in", "co.jp", "com.br",
                   "co.nz", "co.za", "com.cn", "com.sg", "com.mx"}

# Extra networks that ipaddress.is_global already excludes, kept explicit for clarity.
_EXTRA_BLOCKED = [ipaddress.ip_network(n) for n in (
    "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "64:ff9b::/96", "2002::/16")]


class AnalysisError(Exception):
    """Internal, sanitised error carrying a user-safe message."""


def ip_is_public(ip) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return ip_is_public(addr.ipv4_mapped)
    if not addr.is_global:
        return False
    if addr.is_multicast or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        return False
    return not any(addr in net for net in _EXTRA_BLOCKED if net.version == addr.version)


def default_resolver(host, port):
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    seen, out = set(), []
    for fam, _t, _p, _c, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def registrable_domain(host: str) -> str:
    host = (host or "").lower().rstrip(".")
    if not host or IP_REGEX.match(host) or ":" in host:
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in _MULTI_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _fmt_url(scheme, host, port, path):
    h = f"[{host}]" if ":" in host else host
    p = "" if port in (80, 443) else f":{port}"
    return f"{scheme}://{h}{p}{path}"


def _check(cid, name, status, detail):
    return {"id": cid, "name": name, "status": status, "detail": detail}


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self):
        raw = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class SecurityAnalyzer:
    def __init__(self, max_redirects=5, hop_timeout=5.0, total_timeout=15.0,
                 allowed_ports=(80, 443), resolver=default_resolver,
                 ip_policy=ip_is_public, ssl_context=None):
        self.max_redirects = max_redirects
        self.hop_timeout = hop_timeout
        self.total_timeout = total_timeout
        self.allowed_ports = tuple(allowed_ports)
        self.resolver = resolver
        self.ip_policy = ip_policy
        self.ssl_context = ssl_context or ssl.create_default_context()

    # ---------- validation ----------
    def _parse(self, url):
        """Return (scheme, host, port, path_with_query, had_credentials) or raise."""
        url = (url or "").strip()
        if not url:
            raise AnalysisError("No URL provided.")
        if len(url) > MAX_URL_LENGTH:
            raise AnalysisError("URL is too long.")
        if any(ord(c) < 33 or ord(c) == 127 for c in url):
            raise AnalysisError("URL contains whitespace or control characters.")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
            url = "http://" + url
        try:
            sp = urlsplit(url)
            port = sp.port
            host = sp.hostname
        except ValueError:
            raise AnalysisError("URL is malformed.")
        if sp.scheme.lower() not in ("http", "https"):
            raise AnalysisError("Only http and https URLs can be inspected.")
        if not host:
            raise AnalysisError("URL has no hostname.")
        host = host.rstrip(".").lower()
        try:
            host_idna = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise AnalysisError("Hostname is not valid.")
        if len(host_idna) > 253:
            raise AnalysisError("Hostname is too long.")
        if port is None:
            port = 443 if sp.scheme.lower() == "https" else 80
        path = urlunsplit(("", "", sp.path or "/", sp.query, ""))
        creds = bool(sp.username or sp.password)
        return sp.scheme.lower(), host_idna, port, path, creds

    def _resolve_public(self, host, port):
        """Resolve and validate. Returns (public_ips, blocked_flag, dns_failed)."""
        try:
            ips = self.resolver(host, port)
        except (socket.gaierror, UnicodeError, OSError):
            return [], False, True
        if not ips:
            return [], False, True
        if not all(self.ip_policy(ip) for ip in ips):
            return [], True, False
        return ips, False, False

    # ---------- network ----------
    def _request_head(self, scheme, host, ip, port, path):
        """HEAD (fallback GET) reading headers only. Returns (status, headers, tls_info)."""
        last = None
        for method in ("HEAD", "GET"):
            if scheme == "https":
                conn = _PinnedHTTPS(host, ip, port, self.hop_timeout, self.ssl_context)
            else:
                conn = _PinnedHTTP(host, ip, port, self.hop_timeout)
            try:
                conn.request(method, path, headers={
                    "User-Agent": USER_AGENT, "Accept": "*/*",
                    "Connection": "close", "Range": "bytes=0-0"})
                resp = conn.getresponse()  # headers only; body is never read
                headers = {k.lower(): v for k, v in resp.getheaders()}
                if sum(len(k) + len(v) for k, v in headers.items()) > MAX_HEADER_BYTES:
                    raise AnalysisError("Response headers exceeded the size limit.")
                tls = None
                if scheme == "https" and conn.sock is not None:
                    tls = self._tls_info(conn.sock)
                status = resp.status
                last = (status, headers, tls)
                if method == "HEAD" and status in (405, 501):
                    continue
                return last
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        return last

    @staticmethod
    def _tls_info(sock):
        cert = sock.getpeercert() or {}
        info = {"version": sock.version()}
        try:
            na = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            nb = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            info["not_after"] = na.date().isoformat()
            info["not_before"] = nb.date().isoformat()
            info["days_remaining"] = (na - datetime.now(timezone.utc)).days
        except (KeyError, ValueError):
            pass

        def flat(rdns):
            d = {}
            for rdn in rdns or ():
                for k, v in rdn:
                    d[k] = v
            return d
        info["issuer"] = flat(cert.get("issuer")).get("organizationName") or \
            flat(cert.get("issuer")).get("commonName")
        info["subject_cn"] = flat(cert.get("subject")).get("commonName")
        return info

    # ---------- main ----------
    def analyze(self, url):
        started = time.monotonic()
        result = {"original_url": (url or "")[:MAX_URL_LENGTH], "chain": [],
                  "final_url": None, "checks": [], "warnings": [],
                  "dns": None, "certificate": None, "completed": False}
        checks = result["checks"]

        try:
            scheme, host, port, path, creds = self._parse(url)
        except AnalysisError as e:
            checks.append(_check("url_format", "URL format", FAILED, str(e)))
            result["summary"] = self._summary(checks)
            return result
        checks.append(_check("url_format", "URL format", PASSED, "URL is well-formed."))
        if creds:
            checks.append(_check("credentials", "Embedded credentials", WARNING,
                                 "The URL contains 'user@' style credentials, a trick used to disguise the "
                                 "real host. The real host is the part after '@'; the credentials were ignored."))
        original_host = host
        original_scheme = scheme
        if IP_REGEX.match(host) or ":" in host:
            checks.append(_check("ip_host", "Host type", WARNING,
                                 "The URL uses an IP address instead of a domain name."))
        if any(host == s or host.endswith("." + s) for s in SHORTENER_DOMAINS):
            checks.append(_check("shortener", "URL shortener", WARNING,
                                 "A link-shortening service hides the real destination; see the redirect chain."))
        if scheme == "http":
            checks.append(_check("http_only", "Transport security", WARNING,
                                 "The submitted URL uses plain HTTP. This is not proof of malicious intent, "
                                 "but data sent over it is not encrypted."))
        if port in self.allowed_ports:
            pass
        else:
            checks.append(_check("port", "Port", FAILED,
                                 "Only standard web ports (80/443) are inspected; this URL uses a different port."))
            result["summary"] = self._summary(checks)
            return result

        visited, hop_idx = set(), 0
        cur_scheme, cur_host, cur_port, cur_path = scheme, host, port, path
        cur_url = _fmt_url(scheme, host, port, path)
        first_dns_done = False
        final_tls, tls_failure = None, None
        stop_reason = None

        while True:
            hop = {"index": hop_idx, "url": cur_url, "host": cur_host, "scheme": cur_scheme,
                   "status": None, "note": None}
            result["chain"].append(hop)

            if time.monotonic() - started > self.total_timeout:
                hop["note"] = "Analysis time limit reached."
                stop_reason = "timeout"
                break
            if cur_url in visited:
                hop["note"] = "Redirect loop detected."
                stop_reason = "loop"
                break
            visited.add(cur_url)

            ips, blocked, dns_failed = self._resolve_public(cur_host, cur_port)
            if not first_dns_done:
                first_dns_done = True
                result["dns"] = self._dns_summary(ips, blocked, dns_failed, checks)
            if blocked:
                hop["note"] = "Destination resolves to a non-public address; request blocked."
                if hop_idx > 0:  # never echo internal redirect targets back to the caller
                    hop["url"] = "[blocked: non-public destination]"
                    hop["host"] = "[blocked]"
                stop_reason = "blocked"
                if hop_idx == 0:
                    checks.append(_check("target_allowed", "Safe to inspect", FAILED,
                                         "This host resolves to a private or reserved network address, so the "
                                         "server refused to contact it."))
                else:
                    checks.append(_check("redirect_target", "Redirect destination", FAILED,
                                         "A redirect pointed to a private or reserved network address. "
                                         "The request was blocked and not followed. Redirecting to internal "
                                         "addresses is a strong red flag."))
                break
            if dns_failed:
                hop["note"] = "Hostname could not be resolved."
                stop_reason = "dns"
                break

            try:
                status, headers, tls = self._request_head(cur_scheme, cur_host, ips[0], cur_port, cur_path)
            except ssl.SSLCertVerificationError as e:
                tls_failure = self._cert_error(e)
                hop["note"] = "TLS certificate could not be verified."
                stop_reason = "tls"
                break
            except ssl.SSLError:
                tls_failure = "The TLS handshake failed (unsupported protocol or misconfigured server)."
                hop["note"] = "TLS handshake failed."
                stop_reason = "tls"
                break
            except (socket.timeout, TimeoutError):
                hop["note"] = "Connection timed out."
                stop_reason = "timeout"
                break
            except AnalysisError as e:
                hop["note"] = str(e)
                stop_reason = "error"
                break
            except (OSError, http.client.HTTPException):
                hop["note"] = "Could not connect to the server."
                stop_reason = "unreachable"
                break

            hop["status"] = status
            if tls:
                final_tls = tls
            location = headers.get("location")
            if status in (301, 302, 303, 307, 308) and location:
                if hop_idx >= self.max_redirects:
                    hop["note"] = "Redirect limit reached."
                    stop_reason = "max_redirects"
                    break
                try:
                    nxt = urljoin(cur_url, location.strip())
                    n_scheme, n_host, n_port, n_path, _c = self._parse(nxt)
                except AnalysisError as e:
                    hop["note"] = f"Redirect target rejected: {e}"
                    checks.append(_check("redirect_target", "Redirect destination", FAILED,
                                         f"A redirect pointed to an invalid or unsupported target ({e})"))
                    stop_reason = "bad_redirect"
                    break
                if n_port not in self.allowed_ports:
                    hop["note"] = "Redirect to a non-standard port; not followed."
                    checks.append(_check("redirect_target", "Redirect destination", WARNING,
                                         "A redirect pointed to a non-standard port and was not followed."))
                    stop_reason = "bad_port"
                    break
                if cur_scheme == "https" and n_scheme == "http":
                    result["warnings"].append("The redirect chain downgrades from HTTPS to HTTP.")
                cur_scheme, cur_host, cur_port, cur_path = n_scheme, n_host, n_port, n_path
                cur_url = _fmt_url(n_scheme, n_host, n_port, n_path)
                hop_idx += 1
                continue
            stop_reason = "final"
            break

        last = result["chain"][-1]
        result["completed"] = stop_reason == "final"
        if result["completed"]:
            result["final_url"] = last["url"]
        result["certificate"] = self._cert_summary(final_tls, tls_failure, cur_scheme, stop_reason)
        self._add_chain_checks(result, checks, stop_reason, original_host, original_scheme,
                               cur_host, cur_scheme, tls_failure, last)
        result["summary"] = self._summary(checks)
        return result

    # ---------- helpers ----------
    @staticmethod
    def _cert_error(e):
        reason = getattr(e, "verify_message", "") or ""
        low = reason.lower()
        if "expired" in low:
            return "The certificate has expired."
        if "self-signed" in low or "self signed" in low:
            return "The certificate is self-signed and not trusted."
        if "hostname" in low or "doesn't match" in low or "does not match" in low:
            return "The certificate does not match the website's hostname."
        if "unable to get local issuer" in low or "unable to verify" in low:
            return "The certificate was issued by an untrusted or unknown authority."
        return "The certificate could not be verified as trustworthy."

    @staticmethod
    def _dns_summary(ips, blocked, failed, checks):
        if failed:
            checks.append(_check("dns", "DNS resolution", FAILED, "The hostname does not resolve."))
            return {"resolved": False, "address_count": 0}
        if blocked:
            return {"resolved": True, "address_count": None, "public": False}
        v6 = sum(1 for i in ips if ":" in i)
        checks.append(_check("dns", "DNS resolution", PASSED,
                             f"Resolved to {len(ips)} public address(es) "
                             f"({len(ips) - v6} IPv4, {v6} IPv6)."))
        return {"resolved": True, "address_count": len(ips), "ipv4": len(ips) - v6,
                "ipv6": v6, "public": True}

    @staticmethod
    def _cert_summary(tls, failure, scheme, stop_reason):
        if failure:
            return {"valid": False, "reason": failure}
        if scheme != "https":
            return None
        if tls:
            return {"valid": True, **tls}
        return None

    def _add_chain_checks(self, result, checks, stop_reason, orig_host, orig_scheme,
                          final_host, final_scheme, tls_failure, last_hop):
        chain = result["chain"]
        # reachability
        if stop_reason == "final":
            checks.append(_check("reachability", "Reachability", PASSED,
                                 f"The server responded (HTTP {last_hop['status']})."))
        elif stop_reason == "timeout":
            checks.append(_check("reachability", "Reachability", UNAVAILABLE,
                                 "The website did not respond in time."))
        elif stop_reason in ("unreachable", "dns"):
            checks.append(_check("reachability", "Reachability", FAILED if stop_reason == "dns" else UNAVAILABLE,
                                 last_hop.get("note") or "Could not connect."))
        elif stop_reason == "max_redirects":
            checks.append(_check("reachability", "Reachability", WARNING,
                                 f"Stopped after {self.max_redirects} redirects."))
        elif stop_reason == "loop":
            checks.append(_check("reachability", "Reachability", WARNING,
                                 "The site redirects in a loop."))

        # redirects
        redirects = [h for h in chain if h.get("status") in (301, 302, 303, 307, 308)]
        if not redirects:
            checks.append(_check("redirects", "Redirect chain", PASSED if stop_reason == "final" else UNAVAILABLE,
                                 "No redirects were observed." if stop_reason == "final"
                                 else "Redirects could not be assessed."))
        elif len(redirects) <= 2 and stop_reason == "final":
            checks.append(_check("redirects", "Redirect chain", PASSED,
                                 f"{len(redirects)} redirect(s) followed."))
        else:
            checks.append(_check("redirects", "Redirect chain", WARNING,
                                 f"{len(redirects)} redirects observed; long chains are used to hide the "
                                 f"final destination, though some legitimate sites do this too."))

        # host change
        if len(chain) > 1 and stop_reason != "blocked":
            hosts = [h["host"] for h in chain]
            if registrable_domain(hosts[-1]) != registrable_domain(orig_host):
                checks.append(_check("host_change", "Destination change", WARNING,
                                     f"The final site ({hosts[-1]}) belongs to a different domain than the "
                                     f"submitted one ({orig_host}). This is normal for link shorteners and "
                                     f"some services, but confirm it is where you expect to land."))
            else:
                checks.append(_check("host_change", "Destination change", PASSED,
                                     "All redirects stay within the same registrable domain."))
            if any(a["scheme"] == "https" and b["scheme"] == "http"
                   for a, b in zip(chain, chain[1:])):
                checks.append(_check("downgrade", "HTTPS downgrade", WARNING,
                                     "The chain moves from HTTPS to unencrypted HTTP."))
            if (IP_REGEX.match(hosts[-1]) or ":" in hosts[-1]) and not (IP_REGEX.match(orig_host) or ":" in orig_host):
                checks.append(_check("final_ip", "Final host type", WARNING,
                                     "The redirect ends on a bare IP address rather than a domain name."))
        else:
            checks.append(_check("host_change", "Destination change", PASSED if stop_reason == "final" else UNAVAILABLE,
                                 "No change of host." if stop_reason == "final" else "Not assessed."))

        # certificate
        if tls_failure:
            checks.append(_check("certificate", "HTTPS certificate", FAILED, tls_failure))
        elif final_scheme == "https" and result["certificate"]:
            c = result["certificate"]
            dr = c.get("days_remaining")
            if dr is not None and dr < 0:
                checks.append(_check("certificate", "HTTPS certificate", FAILED, "The certificate has expired."))
            elif dr is not None and dr <= 14:
                checks.append(_check("certificate", "HTTPS certificate", WARNING,
                                     f"Valid and trusted, but expires in {dr} day(s)."))
            else:
                extra = f" Issued by {c['issuer']}." if c.get("issuer") else ""
                exp = f" Expires {c['not_after']}." if c.get("not_after") else ""
                checks.append(_check("certificate", "HTTPS certificate", PASSED,
                                     "Certificate is trusted and matches the hostname." + extra + exp))
        elif final_scheme == "http":
            checks.append(_check("certificate", "HTTPS certificate", UNAVAILABLE,
                                 "The destination does not use HTTPS, so there is no certificate to inspect."))
        else:
            checks.append(_check("certificate", "HTTPS certificate", UNAVAILABLE,
                                 "Certificate information could not be obtained."))

        # registration data
        checks.append(_check("domain_registration", "Domain registration data", UNAVAILABLE,
                             "WHOIS/RDAP lookups are not enabled in this deployment, so domain age is not "
                             "assessed. A recent registration would not by itself indicate a malicious site."))

    @staticmethod
    def _summary(checks):
        counts = {PASSED: 0, WARNING: 0, FAILED: 0, UNAVAILABLE: 0}
        for c in checks:
            counts[c["status"]] += 1
        if counts[FAILED]:
            verdict = "Problems found"
        elif counts[WARNING]:
            verdict = "Review warnings"
        elif counts[PASSED]:
            verdict = "No problems found"
        else:
            verdict = "Not assessed"
        return {"counts": counts, "verdict": verdict,
                "disclaimer": "These checks inspect redirects, DNS and the TLS certificate only. They do not "
                              "scan page content, so a site passing every check can still be malicious."}
