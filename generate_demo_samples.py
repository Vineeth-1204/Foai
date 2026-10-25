"""
Generates sample URLs and downloadable QR code image files for live demonstrations.
Tests each URL against the core Classical Symbolic AI pipeline to report exact verdicts.
"""
import os
import qrcode
from core.application.analyze import analyze_url

DEMO_DIR = "demo_samples"
os.makedirs(DEMO_DIR, exist_ok=True)

SAMPLE_CASES = [
    {
        "id": "01_safe_legitimate",
        "category": "SAFE",
        "name": "Legitimate Clean Website (HTTPS)",
        "url": "https://www.google.com/search?q=symbolic+artificial+intelligence",
        "description": "Standard HTTPS domain with clean baseline syntax, standard ports, and no suspicious indicators."
    },
    {
        "id": "02_credential_masking_at_symbol",
        "category": "HIGH RISK / CRITICAL",
        "name": "Credential Masking via '@' Authority",
        "url": "http://paypal.com@192.168.1.100/account/verify",
        "description": "Tricks users by placing 'paypal.com' before an '@' symbol, masking the true raw IP destination."
    },
    {
        "id": "03_brand_typosquatting_phishing",
        "category": "HIGH RISK",
        "name": "Brand Typosquatting (A* Match: 'paypa1' -> 'paypal')",
        "url": "http://paypa1.com/login",
        "description": "Host impersonates protected brand 'paypal' with substitution ('1' -> 'l') detected by A* search."
    },
    {
        "id": "04_ip_and_sensitive_keyword",
        "category": "HIGH RISK / CRITICAL",
        "name": "Direct IP Targeting Sensitive Endpoint",
        "url": "http://185.220.101.5/banking/login",
        "description": "Connects directly to an IP host instead of a registered domain while accessing authentication endpoints."
    },
    {
        "id": "05_executable_masquerading",
        "category": "HIGH RISK / CRITICAL",
        "name": "Malware Delivery via Double Extension",
        "url": "https://cloud-share-files.org/annual_report.pdf.exe",
        "description": "Hides executable '.exe' payload behind a document extension '.pdf', indicating drive-by malware."
    },
    {
        "id": "06_unconventional_port",
        "category": "SUSPICIOUS / REVIEW",
        "name": "Non-Standard Network Port",
        "url": "https://portal-portal.org:8443/status",
        "description": "Bypasses standard HTTP(S) ports (80/443) by targeting an unconventional endpoint port 8443."
    },
    {
        "id": "07_insecure_http_transport",
        "category": "LOW / REVIEW",
        "name": "Unencrypted HTTP Transport",
        "url": "http://my-personal-travel-blog.com/about",
        "description": "Communicates over plain HTTP without encryption, leaving traffic open to eavesdropping."
    }
]

def generate_samples():
    print("=" * 80)
    print("GENERATING DEMO SAMPLES & QR CODE IMAGES")
    print("=" * 80)
    
    results = []
    
    for case in SAMPLE_CASES:
        url = case["url"]
        cid = case["id"]
        
        # 1. Generate QR Code Image using qrcode library
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_path = os.path.join(DEMO_DIR, f"{cid}.png")
        img.save(img_path)
        
        # 2. Run through Symbolic AI screening pipeline
        report = analyze_url(url)
        
        verdict = report.verdict.value if hasattr(report.verdict, "value") else str(report.verdict)
        severity = report.highest_severity.value if hasattr(report.highest_severity, "value") else str(report.highest_severity)
        
        rule_ids = [r["rule_id"] if isinstance(r, dict) else r.rule_id for r in report.triggered_rules] if report.triggered_rules else []
        results.append({
            "id": cid,
            "name": case["name"],
            "url": url,
            "verdict": verdict,
            "severity": severity,
            "img_file": f"{cid}.png",
            "img_path": img_path,
            "rules": rule_ids,
            "explanation": report.explanation
        })
        
        print(f"[{cid}]")
        print(f"  URL:       {url}")
        print(f"  Verdict:   {verdict} (Highest Severity: {severity})")
        print(f"  QR Saved:  {img_path}")
        print(f"  Rules:     {', '.join(rule_ids) if rule_ids else '(Clean Baseline)'}")
        print("-" * 80)

    # Write a clean markdown cheat-sheet in demo_samples
    summary_path = os.path.join(DEMO_DIR, "DEMO_CHEAT_SHEET.md")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("# Live Demo Test Links and QR Images\n\n")
        f.write("Use these pre-tested URLs and QR code images in the web dashboard at http://127.0.0.1:5000\n\n")
        f.write("| Sample ID | Expected Verdict | Link / URL | Generated QR Code Image |\n")
        f.write("|---|---|---|---|\n")
        for r in results:
            f.write(f"| **{r['name']}** | `{r['verdict']}` ({r['severity']}) | `{r['url']}` | [`{r['img_file']}`]({r['img_file']}) |\n")
        
        f.write("\n\n## Detailed Scenarios\n\n")
        for r in results:
            f.write(f"### {r['name']}\n")
            f.write(f"- **URL:** `{r['url']}`\n")
            f.write(f"- **AI Verdict:** `{r['verdict']}`\n")
            f.write(f"- **Triggered Rules:** `{', '.join(r['rules']) if r['rules'] else 'None (Clean Baseline)'}`\n")
            f.write(f"- **QR Image:** `{r['img_path']}`\n")
            f.write(f"- **Explanation:** {r['explanation']}\n\n")

    print(f"\nDemo cheat sheet saved to: {summary_path}")

if __name__ == "__main__":
    generate_samples()
