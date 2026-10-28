# Test Results

**Project Name:** EWB Phishing URL Awareness Checker  
**Python Version:** 3.13.6  
**Operating System:** Windows 11  
**Testing Date:** 27 October 2026


## 1. Test Cases and Results

| Test Case | Input URL | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| 1 | `https://www.example.com/login` | No listed warning signs | No listed warning signs found. This does NOT prove safety. | PASS |
| 2 | `http://192.0.2.10/account` | IP address and HTTP warnings | Uses an IP address instead of a familiar domain. Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 3 | `http://example.com@sample.invalid/login` | @ symbol and HTTP warnings | Contains an @ symbol; inspect carefully. Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 4 | `https://a.b.c.d.e.example.invalid/path` | Warning for many hostname segments | Contains many hostname segments/subdomains. | PASS |
| 5 | `https://xn--example.invalid/` | Punycode-style hostname warning | Contains a punycode-style hostname. | PASS |

## 2. Testing Observations

1. **Benign-looking URLs:** Testing showed that URLs with no listed warning signs may still be unsafe. The checker uses basic text-based heuristics and cannot guarantee website safety.

2. **@ Symbol in URLs:** The `@` symbol can be used to make a URL misleading. In a URL such as `http://example.com@sample.invalid/login`, the actual hostname is `sample.invalid`, not `example.com`.

3. **Punycode and Homograph Attacks:** Punycode (`xn--`) is used to represent certain internationalized domain names. Attackers may abuse lookalike characters in domain names to impersonate legitimate websites. However, the presence of Punycode alone does not prove malicious intent.

4. **HTTP Protocol:** URLs using HTTP may expose users to security risks because the connection is not encrypted by TLS. HTTPS also does not guarantee that a website is trustworthy.

## 3. Conclusion

All five test cases passed according to their expected results. The program successfully identified the selected URL warning signs, including IP-based hostnames, the `@` symbol, multiple hostname segments, Punycode markers, and the use of HTTP.

The testing confirms that the checker works for the selected test cases. However, it is an awareness tool rather than a complete phishing detection system. Users should always verify website domains and avoid entering passwords or sensitive information on suspicious websites.

