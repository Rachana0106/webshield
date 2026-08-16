GLOSSARY = {
    "HTTPS": {
        "simple": "HTTPS protects information while it travels between your browser and a website by encrypting the connection.",
        "analogy": "Think of it like putting your message inside a locked envelope instead of sending it on an open postcard."
    },
    "TLS": {
        "simple": "TLS is the security technology used by HTTPS to encrypt network communication and verify the website's certificate.",
        "analogy": "It is the lock-and-key system behind the padlock icon in your browser."
    },
    "Security Header": {
        "simple": "A security header is an instruction a website sends to the browser telling it how to apply certain security protections.",
        "analogy": "It is like giving the browser a set of safety rules before it displays the page."
    },
    "CSP": {
        "simple": "Content Security Policy (CSP) controls which scripts, styles, images and other resources a browser is allowed to load.",
        "analogy": "Think of CSP as a guest list: only approved resources should be allowed into the page."
    },
    "XSS": {
        "simple": "Cross-Site Scripting (XSS) happens when attacker-controlled script is able to run inside a website in another user's browser.",
        "analogy": "It is like someone slipping an unwanted instruction into a page that the browser mistakenly trusts."
    },
    "Clickjacking": {
        "simple": "Clickjacking tries to trick a user into clicking something different from what they think they are clicking, often using hidden or disguised frames.",
        "analogy": "Imagine a transparent button placed over the button you intended to press."
    },
    "Cookie": {
        "simple": "A cookie is a small piece of data that a website stores in the browser. Cookies can remember sessions, preferences and other information.",
        "analogy": "It is like a small note the website asks your browser to keep for later."
    },
    "HttpOnly": {
        "simple": "HttpOnly tells the browser not to expose a cookie directly to JavaScript.",
        "analogy": "It places the cookie behind a door that page scripts cannot normally open."
    },
    "Secure Cookie": {
        "simple": "The Secure attribute tells the browser to send a cookie only over HTTPS.",
        "analogy": "It tells the browser to use only the encrypted road when carrying that cookie."
    },
    "SameSite": {
        "simple": "SameSite controls when a browser sends a cookie with requests that originate from another website.",
        "analogy": "It is a rule about when your website's ID card is allowed to travel with cross-site requests."
    },
    "CSRF": {
        "simple": "Cross-Site Request Forgery (CSRF) is an attack that tries to make a logged-in user's browser send an unwanted request.",
        "analogy": "It is like someone secretly preparing a form and trying to make you submit it while you are already signed in."
    },
    "CORS": {
        "simple": "Cross-Origin Resource Sharing (CORS) controls which other websites are allowed to read certain responses from a website in the browser.",
        "analogy": "It is a browser permission list deciding which other websites may borrow data."
    },
    "Mixed Content": {
        "simple": "Mixed content occurs when an HTTPS page loads some resources over insecure HTTP.",
        "analogy": "It is like using a locked front door but leaving one window open."
    },
    "SRI": {
        "simple": "Subresource Integrity (SRI) lets a browser verify that a third-party script or stylesheet has not changed unexpectedly.",
        "analogy": "It works like checking a package seal before using what is inside."
    },
    "Server Banner": {
        "simple": "A server banner is information a website may reveal about the web server or platform it uses.",
        "analogy": "It is like a name badge on the server. Sometimes the badge tells visitors more than they need to know."
    },
    "Confidence": {
        "simple": "Confidence tells you how certain WebShield is that the reported observation is correct.",
        "analogy": "High confidence means WebShield directly observed the condition; low confidence means it is only a clue that needs manual checking."
    },
    "Severity": {
        "simple": "Severity estimates how important a security finding could be if it affects the website.",
        "analogy": "Severity is about possible impact, while confidence is about how sure we are."
    }
}

FINDING_HELP = {
    "missing_csp": {
        "friendly_title": "Browser script protection is not configured",
        "term": "CSP",
        "what_it_means": "WebShield could not find a Content-Security-Policy header in the website response.",
        "why_care": "A well-designed CSP can reduce the impact of some script-injection problems, including certain XSS attacks.",
        "does_it_mean_hacked": "No. A missing CSP does not mean the website is hacked and does not prove that an XSS vulnerability exists.",
    },
    "weak_csp": {
        "friendly_title": "Content Security Policy could be stronger",
        "term": "CSP",
        "what_it_means": "A Content-Security-Policy exists, but WebShield found settings that may make the policy less restrictive.",
        "why_care": "A weak CSP may provide less protection if another client-side weakness is present.",
        "does_it_mean_hacked": "No. This is a hardening concern, not proof of exploitation.",
    },
    "missing_nosniff": {
        "friendly_title": "Browser file-type protection is missing",
        "term": "Security Header",
        "what_it_means": "The website does not send X-Content-Type-Options: nosniff.",
        "why_care": "This header tells browsers not to guess a different content type for a response.",
        "does_it_mean_hacked": "No. It means one browser hardening control is not configured.",
    },
    "missing_referrer": {
        "friendly_title": "Referrer information is not explicitly limited",
        "term": "Security Header",
        "what_it_means": "The website does not send an explicit Referrer-Policy header.",
        "why_care": "A Referrer-Policy can reduce how much page-address information is shared when a user follows links or loads external resources.",
        "does_it_mean_hacked": "No. This is mainly a privacy and hardening recommendation.",
    },
    "missing_permissions": {
        "friendly_title": "Browser feature permissions are not explicitly restricted",
        "term": "Security Header",
        "what_it_means": "The website does not send a Permissions-Policy header.",
        "why_care": "Permissions-Policy can limit access to browser features such as camera, microphone or location where those features are not needed.",
        "does_it_mean_hacked": "No. This is an additional hardening control.",
    },
    "clickjacking": {
        "friendly_title": "Clickjacking protection was not detected",
        "term": "Clickjacking",
        "what_it_means": "WebShield did not detect X-Frame-Options or a CSP frame-ancestors rule.",
        "why_care": "Frame restrictions can stop another website from embedding your pages in ways that may be used to mislead users.",
        "does_it_mean_hacked": "No. This does not confirm a clickjacking attack is possible; it means the expected browser-side protection was not visible.",
    },
    "cookie_secure": {
        "friendly_title": "A cookie can be sent without the Secure rule",
        "term": "Secure Cookie",
        "what_it_means": "A cookie was observed without the Secure attribute on an HTTPS website.",
        "why_care": "Sensitive cookies should normally travel only over encrypted HTTPS connections.",
        "does_it_mean_hacked": "No. WebShield is reporting a cookie configuration weakness.",
    },
    "cookie_httponly": {
        "friendly_title": "A cookie is accessible to page JavaScript",
        "term": "HttpOnly",
        "what_it_means": "A cookie was observed without the HttpOnly attribute.",
        "why_care": "HttpOnly can reduce direct JavaScript access to sensitive session cookies.",
        "does_it_mean_hacked": "No. Some cookies legitimately need JavaScript access, so the cookie's purpose should be reviewed.",
    },
    "cookie_samesite": {
        "friendly_title": "A cookie has no explicit cross-site rule",
        "term": "SameSite",
        "what_it_means": "A cookie was observed without an explicit SameSite attribute.",
        "why_care": "SameSite can help control when cookies are attached to requests coming from other websites.",
        "does_it_mean_hacked": "No. The correct value depends on how the application works.",
    },
    "csrf_hint": {
        "friendly_title": "Form protection needs manual verification",
        "term": "CSRF",
        "what_it_means": "WebShield did not see an obvious anti-CSRF token in a POST form.",
        "why_care": "Some state-changing forms need protection against unwanted requests sent from other websites.",
        "does_it_mean_hacked": "No. This does not prove CSRF protection is absent. Frameworks can protect requests in ways that are not visible in the HTML.",
    },
    "mixed_content": {
        "friendly_title": "An HTTPS page loads an insecure HTTP resource",
        "term": "Mixed Content",
        "what_it_means": "The page is protected by HTTPS, but at least one linked resource uses plain HTTP.",
        "why_care": "Insecure resources can weaken the protection users expect from an HTTPS page.",
        "does_it_mean_hacked": "No. It is a transport-security configuration issue.",
    },
    "server_disclosure": {
        "friendly_title": "The website reveals server/platform information",
        "term": "Server Banner",
        "what_it_means": "A response header identifies the server or hosting platform.",
        "why_care": "Reducing unnecessary technology disclosure can make passive fingerprinting less informative.",
        "does_it_mean_hacked": "No. Technology disclosure alone is usually a low-risk information finding.",
    },
    "cors_credentials_wildcard": {
        "friendly_title": "Cross-site data sharing configuration needs attention",
        "term": "CORS",
        "what_it_means": "The response advertises a broad cross-origin policy together with credential-related behavior.",
        "why_care": "Unsafe CORS combinations can expose data to websites that should not be able to read it.",
        "does_it_mean_hacked": "No. This is a configuration finding and should be confirmed against the application's intended behavior.",
    },
    "cors_wildcard": {
        "friendly_title": "The website allows any origin to read this response",
        "term": "CORS",
        "what_it_means": "Access-Control-Allow-Origin is set to * for this response.",
        "why_care": "That can be completely appropriate for public data, but it is not suitable for every type of response.",
        "does_it_mean_hacked": "No. Whether this is risky depends on the data and authentication model.",
    },
    "sri_missing": {
        "friendly_title": "A third-party script has no integrity check",
        "term": "SRI",
        "what_it_means": "A script is loaded from another domain without an integrity attribute.",
        "why_care": "SRI can help detect unexpected changes to fixed-version third-party resources.",
        "does_it_mean_hacked": "No. SRI is a supply-chain hardening control and is not appropriate for every dynamic resource.",
    },
    "http_site": {
        "friendly_title": "The website connection is not encrypted",
        "term": "HTTPS",
        "what_it_means": "The final website address uses HTTP instead of HTTPS.",
        "why_care": "Information travelling over HTTP is not protected by normal HTTPS encryption.",
        "does_it_mean_hacked": "No. But users should not send sensitive information over an unencrypted connection.",
    },
    "tls_invalid": {
        "friendly_title": "The website certificate could not be validated",
        "term": "TLS",
        "what_it_means": "WebShield could not validate the TLS certificate used by the website.",
        "why_care": "A valid certificate helps browsers establish an encrypted connection to the intended website.",
        "does_it_mean_hacked": "Not necessarily. Certificate expiry, hostname mismatch or trust-chain problems can cause validation failure.",
    },
    "tls_expiring": {
        "friendly_title": "The website certificate will expire soon",
        "term": "TLS",
        "what_it_means": "The certificate is currently valid but is close to its expiry date.",
        "why_care": "An expired certificate can cause browser warnings and disrupt secure access.",
        "does_it_mean_hacked": "No. This is a maintenance warning.",
    },
    "client_pattern": {
        "friendly_title": "A JavaScript pattern deserves manual review",
        "term": "XSS",
        "what_it_means": "WebShield found a JavaScript feature that can be safe or unsafe depending on how data reaches it.",
        "why_care": "Functions such as eval() or HTML-writing APIs become risky when untrusted input reaches them.",
        "does_it_mean_hacked": "No. Presence of the pattern alone is not a vulnerability.",
    },
    "possible_secret": {
        "friendly_title": "The page contains text that looks sensitive",
        "term": "Security Header",
        "what_it_means": "Public page content matched a pattern commonly associated with secrets or debugging information.",
        "why_care": "Real credentials, tokens or detailed error traces should not normally be exposed publicly.",
        "does_it_mean_hacked": "No. Pattern matching can produce false positives, so manual verification is required.",
    },
}
