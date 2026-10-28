
import re
from urllib.parse import urlparse

INFO_MESSAGES = (
    "No URL entered",
    "Could not identify",
    "No listed warning",
    "This text is not a valid",
)


def has_warnings(findings):
    if not findings:
        return False

    return not findings[0].startswith(INFO_MESSAGES)


def inspect_url(raw_url):
    """Check visible URL text for selected warning signs."""
    url = raw_url.strip()
    findings = []

    if not url:
        return ["No URL entered."]

    # Add a default scheme if missing
    candidate = url if "://" in url else "http://" + url

    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return ["This text is not a valid URL format."]

    if not host:
        return ["Could not identify a hostname."]

    if "@" in candidate:
        findings.append(
            "Contains an @ symbol; inspect carefully."
        )

    # Check 2: Unusually long URL
    if len(url) > 100:
        findings.append(
            "Unusually long URL (over 100 characters)."
        )

    # Check 3: IP address as hostname
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        findings.append(
            "Uses an IP address instead of a familiar domain."
        )

    # Check 4: Many hostname segments
    labels = [part for part in host.split(".") if part]

    if len(labels) >= 5:
        findings.append(
            "Contains many hostname segments/subdomains."
        )

    # Check 5: Punycode marker
    if "xn--" in host:
        findings.append(
            "Contains a punycode-style hostname."
        )

    # Check 6: Plain HTTP scheme
    if parsed.scheme.lower() == "http":
        findings.append(
            "Uses HTTP. HTTPS alone does not prove trust."
        )

    # Default message when no warnings are found
    if not findings:
        findings.append(
            "No listed warning signs found. "
            "This does NOT prove safety."
        )

    return findings


def main():
    """CLI loop for inspecting URLs until quit."""
    print("EWB Phishing URL Awareness Checker")
    print("Text checks only - this program does not open URLs.")

    while True:
        raw_url = input(
            "\nEnter a sample URL (or type q to quit): "
        )

        if raw_url.strip().lower() in ("q", "quit", "exit"):
            print("Goodbye! Stay alert online.")
            break

        findings = inspect_url(raw_url)

        print("\nResult:")
        for item in findings:
            print("- " + item)

        if has_warnings(findings):
            print(
                "\nREVIEW CAREFULLY: "
                f"{len(findings)} warning sign(s) found."
            )

        print("\nNever enter passwords from unexpected links.")


if __name__ == "__main__":
    main()

