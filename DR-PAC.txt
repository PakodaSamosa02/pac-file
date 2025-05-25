function FindProxyForURL(url, host) {
    // Define a regular expression for private IP ranges
    var privateIP = /^(0|10|127|192\.168|172\.(1[6-9]|2[0-9]|3[01])|169\.254|192\.88\.99)\.[0-9.]+$/;

    // Resolve the host to an IP address
    var resolved_ip = dnsResolve(host);

    // Check for private IP addresses or specific network ranges
    if (isInNet(resolved_ip, "192.0.2.0", "255.255.255.0") || privateIP.test(resolved_ip)) {
        return "DIRECT";
    }

    // Define a regular expression for trusted domains
    var trust = /^(trust|ips)\.(zscaler|zscalerone|zscalertwo|zscalerthree|zsdemo|zscalergov|zscloud|zsfalcon|zdxcloud|zdxpreview)\.(com|net)$/;

    // Define a regular expression for IAM domains
    var iam = /^.*\.(zslogin|zsloginbeta|zslogindemo)\.net$/;

    // Match trusted or IAM domains and allow direct traffic
    if (trust.test(host) || iam.test(host) || /^trust\.zscaler\.us$/.test(host) || /^config\.zscaler\.com$/.test(host)) {
        return "DIRECT";
    }

    // Bypass for ZPA infrastructure
    if (isInNet(resolved_ip, "100.64.0.0", "255.255.0.0") ||
        shExpMatch(host, "*.private.zscaler.com") ||
        shExpMatch(host, "*.zpath.net")) {
        return "DIRECT";
    }

    // Block access to specific domains unconditionally during ZIA DR
    if (shExpMatch(host, "*.example.com") || shExpMatch(host, "example.com") ||
        localHostOrDomainIs(host, "www.blockedsite.com") ||
        shExpMatch(host, "*.cricbuzz.com") || shExpMatch(host, "cricbuzz.com") ||
        shExpMatch(host, "*.poker.com") || shExpMatch(host, "poker.com")) {
        return "BLOCK";
    }

    // Use ZIA PSE as the primary proxy and a third-party proxy as the secondary during ZIA DR
    return "PROXY 35.84.253.72:443";
}