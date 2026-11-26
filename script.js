
const form = document.getElementById("scannerForm");
const input = document.getElementById("urlInput");
const results = document.getElementById("results");
const button = document.getElementById("scanButton");

form.addEventListener("submit", function(event) {
    event.preventDefault();
    scanURL();
});

function scanURL() {

    const value = input.value.trim();

    if (!value) {
        showMessage("Enter a URL first.", "danger");
        return;
    }

    let url;

    try {
        url = new URL(value);
    } catch {
        showMessage(
            "Invalid URL. Include https:// or http://",
            "danger"
        );
        return;
    }

    if (!["https:", "http:"].includes(url.protocol)) {
        showMessage("Unsupported URL protocol.", "danger");
        return;
    }

    if (!url.hostname.includes(".") ||
        url.hostname.startsWith(".") ||
        url.hostname.endsWith(".")) {

        showMessage("Invalid hostname.", "danger");
        return;
    }

    button.disabled = true;
    button.textContent = "ANALYZING...";

    results.replaceChildren();

    setTimeout(() => {

        let score = 0;
        const findings = [];

        const hostname = url.hostname.toLowerCase();

        // HTTPS check

        if (url.protocol === "https:") {

            findings.push({
                text: "HTTPS protocol detected.",
                type: "safe"
            });

        } else {

            score += 20;

            findings.push({
                text: "Connection does not use HTTPS.",
                type: "warning"
            });
        }

        // IP address check

        const ipPattern =
            /^(\d{1,3}\.){3}\d{1,3}$/;

        if (ipPattern.test(hostname)) {

            const validIP = hostname.split(".")
                .every(part =>
                    Number(part) >= 0 &&
                    Number(part) <= 255
                );

            if (validIP) {

                score += 25;

                findings.push({
                    text: "URL uses an IP address instead of a domain.",
                    type: "warning"
                });
            }
        }

        // URL length

        if (url.href.length > 100) {

            score += 10;

            findings.push({
                text: "Unusually long URL detected.",
                type: "warning"
            });
        }

        // Suspicious keywords

        const keywords = [
            "login",
            "verify",
            "account",
            "password",
            "secure",
            "wallet",
            "update"
        ];

        const matches = keywords.filter(word =>
            hostname.split(/[.-]/).includes(word)
        );

        if (matches.length > 0) {

            score += 15;

            findings.push({
                text: "Potentially suspicious keywords: " +
                    matches.join(", "),
                type: "warning"
            });
        }

        // Punycode check

        if (hostname.includes("xn--")) {

            score += 25;

            findings.push({
                text: "Punycode domain encoding detected.",
                type: "warning"
            });
        }

        // Too many domain sections

        if (hostname.split(".").length > 4) {

            score += 10;

            findings.push({
                text: "Unusually many domain sections detected.",
                type: "warning"
            });
        }

        // Embedded credentials

        if (url.username || url.password) {

            score += 25;

            findings.push({
                text: "URL contains embedded user information.",
                type: "danger"
            });
        }

        score = Math.min(score, 100);

        let level = "LOW";
        let className = "safe";

        if (score >= 25) {
            level = "MEDIUM";
            className = "warning";
        }

        if (score >= 50) {
            level = "HIGH";
            className = "danger";
        }

        displayResults(
            url,
            score,
            level,
            className,
            findings
        );

        button.disabled = false;
        button.textContent = "ANALYZE URL";

    }, 700);
}

function displayResults(
    url,
    score,
    level,
    className,
    findings
) {

    const box = document.createElement("div");
    box.className = "result-box";

    const heading = document.createElement("h2");
    heading.textContent = "SCAN REPORT";

    const target = document.createElement("p");
    target.textContent = "Target: " + url.href;

    const risk = document.createElement("p");
    risk.textContent = "Risk indicators: " + score + "/100";
    risk.className = className;

    const assessment = document.createElement("p");
    assessment.textContent = "Assessment: " + level;
    assessment.className = className;

    const divider = document.createElement("hr");

    const findingsTitle = document.createElement("h3");
    findingsTitle.textContent = "SCAN FINDINGS";

    box.append(
        heading,
        target,
        risk,
        assessment,
        divider,
        findingsTitle
    );

    findings.forEach(item => {

        const line = document.createElement("p");

        line.textContent = "• " + item.text;
        line.className = item.type;

        box.appendChild(line);
    });

    const disclaimer = document.createElement("p");

    disclaimer.className = "warning";

    disclaimer.textContent =
        "This is a heuristic assessment, not a verified safety verdict.";

    box.appendChild(disclaimer);

    results.replaceChildren(box);
}

function showMessage(message, type) {

    const paragraph = document.createElement("p");

    paragraph.className = type;
    paragraph.textContent = message;

    results.replaceChildren(paragraph);
}

