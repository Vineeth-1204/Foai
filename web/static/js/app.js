/**
 * Frontend Controller for Explainable URL Risk Screening Dashboard.
 * Strictly presentation logic: renders structured JSON from /api/analyze.
 * Contains ZERO inference, scoring, or parsing logic.
 */
document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("analyze-form");
    const qrForm = document.getElementById("qr-form");
    const urlInput = document.getElementById("url-input");
    const qrFileInput = document.getElementById("qr-file-input");
    const validationMsg = document.getElementById("validation-msg");
    const loadingSpinner = document.getElementById("loading-spinner");
    const resultsArea = document.getElementById("results-area");

    const tabUrlMode = document.getElementById("tab-url-mode");
    const tabQrMode = document.getElementById("tab-qr-mode");
    const qrDecodedBanner = document.getElementById("qr-decoded-banner");
    const qrDecodedText = document.getElementById("qr-decoded-text");

    // Plain-language summary elements
    const simpleSummarySection = document.getElementById("simple-summary-section");
    const summaryIcon = document.getElementById("summary-icon");
    const summaryTag = document.getElementById("summary-tag");
    const summaryHeadline = document.getElementById("summary-headline");
    const summaryBody = document.getElementById("summary-body");
    const summaryActionText = document.getElementById("summary-action-text");
    const signalTransportVal = document.getElementById("signal-transport-val");
    const signalIdentityVal = document.getElementById("signal-identity-val");
    const signalIntentVal = document.getElementById("signal-intent-val");

    // Verdict elements
    const verdictBanner = document.getElementById("verdict-banner");
    const verdictBadge = document.getElementById("verdict-badge");
    const severityBadge = document.getElementById("severity-badge");
    const verdictExplanation = document.getElementById("verdict-explanation");
    const tokensGrid = document.getElementById("tokens-grid");

    // Tab switching
    tabUrlMode.addEventListener("click", () => {
        tabUrlMode.classList.add("active");
        tabQrMode.classList.remove("active");
        form.classList.remove("hidden");
        qrForm.classList.add("hidden");
        clearValidation();
    });

    tabQrMode.addEventListener("click", () => {
        tabQrMode.classList.add("active");
        tabUrlMode.classList.remove("active");
        qrForm.classList.remove("hidden");
        form.classList.add("hidden");
        clearValidation();
    });

    // Disclaimer & A* elements
    const safeDisclaimerSection = document.getElementById("safe-disclaimer-section");
    const safeDisclaimerText = document.getElementById("safe-disclaimer-text");
    const astarSection = document.getElementById("astar-section");
    const astarSource = document.getElementById("astar-source");
    const astarTarget = document.getElementById("astar-target");
    const astarCost = document.getElementById("astar-cost");
    const astarOpsList = document.getElementById("astar-operations-list");

    // Risk factors & rules
    const riskFactorsList = document.getElementById("risk-factors-list");
    const triggeredRulesList = document.getElementById("triggered-rules-list");

    // Proof tree
    const interactiveProofTree = document.getElementById("interactive-proof-tree");
    const rawProofTree = document.getElementById("raw-proof-tree");
    const toggleTextProofBtn = document.getElementById("toggle-text-proof");

    // Toggle Raw Text Proof Tree
    toggleTextProofBtn.addEventListener("click", () => {
        rawProofTree.classList.toggle("hidden");
    });

    // Preset button handlers
    document.querySelectorAll(".preset-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            const url = btn.getAttribute("data-url");
            if (url) {
                // Switch to manual mode if in QR mode
                tabUrlMode.click();
                urlInput.value = url;
                qrDecodedBanner.classList.add("hidden");
                submitUrl(url);
            }
        });
    });

    // Form submission handler
    form.addEventListener("submit", (e) => {
        e.preventDefault();
        const url = urlInput.value.trim();
        if (!url) {
            showValidation("Please enter a URL to analyze.");
            return;
        }
        qrDecodedBanner.classList.add("hidden");
        submitUrl(url);
    });

    // QR Form submission handler
    qrForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (!qrFileInput.files || qrFileInput.files.length === 0) {
            showValidation("Please select a QR code image to upload.");
            return;
        }

        const file = qrFileInput.files[0];
        clearValidation();
        qrDecodedBanner.classList.add("hidden");
        loadingSpinner.classList.remove("hidden");
        resultsArea.classList.add("hidden");

        const formData = new FormData();
        formData.append("qr_image", file);

        try {
            const response = await fetch("/api/analyze-qr", {
                method: "POST",
                body: formData,
            });

            const data = await response.json();

            if (!data.success) {
                showValidation(data.error || "Could not decode QR code.");
                return;
            }

            if (data.decoded_text) {
                qrDecodedText.textContent = data.decoded_text;
                qrDecodedBanner.classList.remove("hidden");
                urlInput.value = data.decoded_text;
            }

            if (data.error && !data.report) {
                // Non-URL QR content (e.g. plain text, vcard)
                showValidation(data.error);
                return;
            }

            if (data.report) {
                renderResults(data.report);
            }
        } catch (err) {
            showValidation("Network fault communicating with the local analysis engine: " + err.message);
        } finally {
            loadingSpinner.classList.add("hidden");
        }
    });

    function showValidation(msg) {
        validationMsg.textContent = msg;
        validationMsg.classList.remove("hidden");
    }

    function clearValidation() {
        validationMsg.textContent = "";
        validationMsg.classList.add("hidden");
    }

    async function submitUrl(url) {
        clearValidation();
        loadingSpinner.classList.remove("hidden");
        resultsArea.classList.add("hidden");

        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: url }),
            });

            const data = await response.json();
            renderResults(data);
        } catch (err) {
            showValidation("Network fault communicating with the local analysis engine: " + err.message);
        } finally {
            loadingSpinner.classList.add("hidden");
        }
    }

    function updateSimpleSummary(report) {
        if (!simpleSummarySection) return;

        const verdict = report.verdict || "REVIEW";
        const pats = report.triggered_patterns || [];
        const comp = report.parsed_components || {};
        const hasAstar = !!report.astar_evidence;
        const scheme = (comp.scheme || "").toLowerCase();
        const isHttp = scheme === "http";
        const host = comp.hostname || "";
        const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
        const hasNonStdPort = !!comp.port && !["80", "443"].includes(String(comp.port));

        let icon = "🛡️";
        let tag = "Clean & Legitimate";
        let headline = "No Suspicious Activity Found";
        let body = "This website appears safe and genuine. No deceptive patterns, brand impersonation, or credential harvesting indicators were found. The link complies with standard web security conventions.";
        let action = "Safe to visit for standard web browsing.";
        let styleClass = "safe";

        let transportVal = isHttp ? (hasNonStdPort ? `Insecure (Port ${comp.port})` : "Unencrypted (HTTP)") : "Secure (HTTPS)";
        let identityVal = isIp ? "Raw IP Host" : "Legitimate Domain";
        let intentVal = "Safe / No Risk";

        if (verdict === "SAFE") {
            icon = "🛡️";
            tag = "Clean & Legitimate";
            headline = "No Suspicious Activity Found";
            body = "This website appears safe and genuine. No deceptive patterns, brand impersonation, or credential harvesting indicators were found. The link complies with standard web security conventions.";
            action = "Safe to open and browse.";
            styleClass = "safe";
            identityVal = "Legitimate Domain";
            intentVal = "Safe / No Risk";
        } else if (verdict === "REVIEW") {
            icon = "⚠️";
            tag = "Caution Advised";
            headline = "Caution: Unusual Configuration Detected";
            body = "This website uses non-standard technical settings (such as an unusual port number or unencrypted HTTP transport). While no active phishing pattern was found, exercise normal caution.";
            action = "Proceed with caution. Verify the destination if you were not expecting a custom server setup.";
            styleClass = "review";
            identityVal = isIp ? "Direct IP Address" : "Unverified Setup";
            intentVal = "Low / Informational";
        } else if (verdict === "SUSPICIOUS") {
            icon = "⚠️";
            tag = "Potential Risk";
            headline = "This Website May Not Be Secure";
            body = "Noticeable warning signs were detected (such as direct numerical IP addressing or a brand name reference without secure encryption). The site could be deceptive or misconfigured.";
            action = "Avoid entering sensitive details, passwords, or personal data on this page.";
            styleClass = "suspicious";
            if (hasAstar) {
                identityVal = `Mimics ${report.astar_evidence.matched_brand}`;
            } else if (isIp) {
                identityVal = "Direct Numerical IP";
            } else {
                identityVal = "Unverified Host";
            }
            intentVal = "Elevated Risk";
        } else if (verdict === "HIGH RISK") {
            icon = "⛔";
            tag = "Severe Risk Alert";
            headline = "Danger: This Website Is Not Secure";
            action = "Do not open this link. Do not enter any login credentials or download files.";
            styleClass = "high-risk";
            intentVal = "Phishing / Theft Detected";

            if (pats.includes("pattern_targeted_brand_phishing")) {
                const brand = report.astar_evidence ? report.astar_evidence.matched_brand : "a known brand";
                body = `Phishing Alert: This website deliberately mimics "${brand}" to deceive you into submitting private passwords or login credentials.`;
                identityVal = `Fake "${brand}" Domain`;
            } else if (pats.includes("pattern_direct_ip_credential_harvesting")) {
                body = "Credential Theft Alert: This link points directly to a raw numerical IP address requesting sensitive login details, bypassing standard domain authentication.";
                identityVal = "Direct IP Address";
            } else if (pats.includes("pattern_userinfo_obfuscation") || pats.includes("pattern_userinfo_deception")) {
                body = "Deceptive URL Alert: This link uses the '@' character to trick your browser into displaying a fake brand name while routing you to an attacker's server.";
                identityVal = "Masked via '@' Trick";
            } else if (pats.includes("pattern_executable_disguise")) {
                body = "Malicious Download Alert: This link attempts to deliver a disguised executable file (.pdf.exe) commonly used to transmit harmful programs or malware.";
                identityVal = "Disguised Executable";
            } else {
                body = "Critical Security Alert: Strong deceptive and high-risk indicators were confirmed by our security rules.";
                identityVal = isIp ? "Direct IP Host" : "Suspicious Host";
            }
        }

        simpleSummarySection.className = `card simple-summary-card ${styleClass}`;
        if (summaryIcon) summaryIcon.textContent = icon;
        if (summaryTag) summaryTag.textContent = tag;
        if (summaryHeadline) summaryHeadline.textContent = headline;
        if (summaryBody) summaryBody.textContent = body;
        if (summaryActionText) summaryActionText.textContent = action;
        if (signalTransportVal) signalTransportVal.textContent = transportVal;
        if (signalIdentityVal) signalIdentityVal.textContent = identityVal;
        if (signalIntentVal) signalIntentVal.textContent = intentVal;
    }

    function renderResults(report) {
        resultsArea.classList.remove("hidden");

        // 0. Render Plain-Language Summary (Simple Terms)
        updateSimpleSummary(report);

        // 1. Render Verdict Card
        const verdict = report.verdict || "REVIEW";
        verdictBadge.textContent = verdict;
        severityBadge.textContent = `Severity: ${report.highest_severity || "NONE"}`;
        verdictExplanation.textContent = report.explanation || "";

        // Reset banner class
        verdictBanner.className = "verdict-banner";
        if (verdict === "SAFE") verdictBanner.classList.add("safe");
        else if (verdict === "REVIEW") verdictBanner.classList.add("review");
        else if (verdict === "SUSPICIOUS") verdictBanner.classList.add("suspicious");
        else if (verdict === "HIGH RISK") verdictBanner.classList.add("high-risk");

        // 2. Render RFC 3986 Lexical Tokens
        tokensGrid.innerHTML = "";
        if (report.parsed_components) {
            const keys = ["scheme", "hostname", "port", "pathname", "query", "fragment", "authority"];
            keys.forEach((key) => {
                const item = document.createElement("div");
                item.className = "token-item";
                item.innerHTML = `
                    <span class="token-key">${key}</span>
                    <span class="token-val" title="${report.parsed_components[key]}">${report.parsed_components[key]}</span>
                `;
                tokensGrid.appendChild(item);
            });
        }

        // 3. Render SAFE Disclaimer
        if (verdict === "SAFE" && report.safe_disclaimer) {
            safeDisclaimerSection.classList.remove("hidden");
            safeDisclaimerText.textContent = report.safe_disclaimer;
        } else {
            safeDisclaimerSection.classList.add("hidden");
        }

        // 4. Render A* Evidence Section
        if (report.astar_evidence) {
            astarSection.classList.remove("hidden");
            astarSource.textContent = report.astar_evidence.observed_label || "-";
            astarTarget.textContent = report.astar_evidence.matched_brand || "-";
            astarCost.textContent = `${report.astar_evidence.edit_cost} edit(s)`;

            astarOpsList.innerHTML = "";
            (report.astar_evidence.operations || []).forEach((op) => {
                const li = document.createElement("li");
                li.textContent = op;
                astarOpsList.appendChild(li);
            });
        } else {
            astarSection.classList.add("hidden");
        }

        // 5. Render Risk Factors
        riskFactorsList.innerHTML = "";
        if (report.risk_factors && report.risk_factors.length > 0) {
            report.risk_factors.forEach((rf) => {
                const div = document.createElement("div");
                let sevClass = "NONE";
                if (rf.includes("[CRITICAL]")) sevClass = "CRITICAL";
                else if (rf.includes("[HIGH]")) sevClass = "HIGH";
                else if (rf.includes("[MEDIUM]")) sevClass = "MEDIUM";
                else if (rf.includes("[LOW]")) sevClass = "LOW";

                div.className = `factor-card ${sevClass}`;
                div.textContent = rf;
                riskFactorsList.appendChild(div);
            });
        } else {
            riskFactorsList.innerHTML = "<p class='text-muted' style='font-size:0.85rem;'>No security risk factors triggered.</p>";
        }

        // 6. Render Triggered Rules
        triggeredRulesList.innerHTML = "";
        if (report.triggered_rules && report.triggered_rules.length > 0) {
            report.triggered_rules.forEach((rule) => {
                const box = document.createElement("div");
                box.className = "rule-box";
                const antecedents = (rule.premises || []).join(" ^ ");
                box.innerHTML = `
                    <div class="rule-header-row">
                        <span class="rule-name">${rule.rule_name}</span>
                        <span class="severity-badge">${rule.severity}</span>
                    </div>
                    <div class="font-mono text-muted" style="font-size:0.75rem;">Rule ID: ${rule.rule_id}</div>
                    <div class="rule-formula">${antecedents} &rArr; ${rule.conclusion}</div>
                `;
                triggeredRulesList.appendChild(box);
            });
        } else {
            triggeredRulesList.innerHTML = "<p class='text-muted' style='font-size:0.85rem;'>No threat pattern rules triggered.</p>";
        }

        // 7. Render Proof Trees
        interactiveProofTree.innerHTML = "";
        if (report.proof_tree_nodes && report.proof_tree_nodes.length > 0) {
            report.proof_tree_nodes.forEach((rootNode) => {
                const nodeEl = createInteractiveNodeElement(rootNode, true);
                interactiveProofTree.appendChild(nodeEl);
            });
        } else {
            interactiveProofTree.innerHTML = "<p class='text-muted font-mono' style='font-size:0.82rem;'>(No proof tree available)</p>";
        }

        // 8. Render Raw Text Proof Tree
        rawProofTree.textContent = report.proof_tree_text || "(No proof tree text available)";
    }

    function createInteractiveNodeElement(node, isRoot = false) {
        const container = document.createElement("div");
        container.className = `tree-node ${isRoot ? "root-node" : ""}`;

        const header = document.createElement("div");
        header.className = "tree-node-header";

        const typePill = document.createElement("span");
        typePill.className = `node-type-pill ${node.node_type === "DERIVED_FACT" ? "derived" : "initial"}`;
        typePill.textContent = node.node_type === "DERIVED_FACT" ? (node.severity || "DERIVED") : "INITIAL";

        const factLabel = document.createElement("span");
        factLabel.textContent = node.fact;

        header.appendChild(typePill);
        header.appendChild(factLabel);

        if (node.rule_id) {
            const ruleTag = document.createElement("span");
            ruleTag.className = "font-mono text-muted";
            ruleTag.style.fontSize = "0.72rem";
            ruleTag.textContent = `(via ${node.rule_id})`;
            header.appendChild(ruleTag);
        }

        if (node.evidence) {
            const evTag = document.createElement("span");
            evTag.className = "evidence-tag font-mono";
            evTag.textContent = `[${node.evidence}]`;
            header.appendChild(evTag);
        }

        container.appendChild(header);

        // Render children
        if (node.children && node.children.length > 0) {
            const childrenContainer = document.createElement("div");
            childrenContainer.className = "tree-children";

            node.children.forEach((child) => {
                childrenContainer.appendChild(createInteractiveNodeElement(child, false));
            });

            container.appendChild(childrenContainer);

            // Collapsible click toggle
            header.addEventListener("click", () => {
                childrenContainer.classList.toggle("hidden");
                header.classList.toggle("collapsed");
            });
        }

        return container;
    }
});
