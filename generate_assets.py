"""
Generates high-resolution PNG icons and technical architecture diagrams
for the Explainable Link & QR Risk Screening presentation.
"""
import os
from PIL import Image, ImageDraw, ImageFont

ICONS_DIR = "generated_assets"
os.makedirs(ICONS_DIR, exist_ok=True)

TEAL = (14, 143, 134, 255)
TEAL_FILL = (14, 143, 134, 30)
DARK_TEAL = (11, 61, 74, 255)
CORAL = (255, 107, 87, 255)
CORAL_FILL = (255, 107, 87, 30)
AMBER = (242, 181, 49, 255)
GREEN = (91, 185, 139, 255)
TEXT_DARK = (18, 32, 43, 255)
BG_LIGHT = (238, 248, 246, 255)
WHITE = (255, 255, 255, 255)
BORDER_GRAY = (207, 227, 224, 255)

def get_font(size=14, bold=False):
    try:
        font_name = "arialbd.ttf" if bold else "arial.ttf"
        return ImageFont.truetype(font_name, size)
    except Exception:
        return ImageFont.load_default()

def create_shield_icon():
    img = Image.new('RGBA', (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    points = [(128, 28), (218, 54), (218, 136), (128, 228), (38, 136), (38, 54)]
    d.polygon(points, fill=TEAL_FILL, outline=TEAL, width=8)
    d.line([(80, 128), (114, 162), (180, 96)], fill=TEAL, width=12)
    img.save(f"{ICONS_DIR}/shield.png")

def create_alert_icon():
    img = Image.new('RGBA', (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    points = [(128, 30), (226, 214), (30, 214)]
    d.polygon(points, fill=CORAL_FILL, outline=CORAL, width=8)
    d.line([(128, 92), (128, 154)], fill=CORAL, width=12)
    d.ellipse([(122, 172), (134, 184)], fill=CORAL)
    img.save(f"{ICONS_DIR}/alert.png")

def create_parser_icon():
    img = Image.new('RGBA', (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # Left bracket <
    d.line([(88, 76), (46, 128), (88, 180)], fill=TEAL, width=10)
    # Slash /
    d.line([(154, 64), (102, 192)], fill=DARK_TEAL, width=10)
    # Right bracket >
    d.line([(168, 76), (210, 128), (168, 180)], fill=TEAL, width=10)
    img.save(f"{ICONS_DIR}/parser.png")

def create_search_icon():
    img = Image.new('RGBA', (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # Magnifying glass circle
    d.ellipse([(44, 44), (160, 160)], outline=TEAL, width=10, fill=TEAL_FILL)
    # Handle
    d.line([(144, 144), (212, 212)], fill=TEAL, width=14)
    # Star inside (A*)
    font = get_font(44, bold=True)
    d.text((102, 102), "A*", fill=DARK_TEAL, font=font, anchor="mm")
    img.save(f"{ICONS_DIR}/search.png")

def create_logic_icon():
    img = Image.new('RGBA', (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # Tree nodes
    # Root
    d.ellipse([(108, 38), (148, 78)], fill=TEAL, outline=DARK_TEAL, width=4)
    # Left child
    d.ellipse([(48, 168), (88, 208)], fill=DARK_TEAL, outline=DARK_TEAL, width=4)
    # Center child
    d.ellipse([(108, 168), (148, 208)], fill=DARK_TEAL, outline=DARK_TEAL, width=4)
    # Right child
    d.ellipse([(168, 168), (208, 208)], fill=DARK_TEAL, outline=DARK_TEAL, width=4)
    # Branches
    d.line([(128, 78), (68, 168)], fill=TEAL, width=6)
    d.line([(128, 78), (128, 168)], fill=TEAL, width=6)
    d.line([(128, 78), (188, 168)], fill=TEAL, width=6)
    img.save(f"{ICONS_DIR}/logic.png")

def create_qr_icon():
    img = Image.new('RGBA', (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # QR outer finder patterns (Top-left, Top-right, Bottom-left)
    def draw_finder(x, y):
        d.rectangle([(x, y), (x+54, y+54)], fill=WHITE, outline=TEAL, width=6)
        d.rectangle([(x+14, y+14), (x+40, y+40)], fill=TEAL)

    draw_finder(42, 42)
    draw_finder(160, 42)
    draw_finder(42, 160)
    # Random QR data bits
    d.rectangle([(160, 160), (180, 180)], fill=DARK_TEAL)
    d.rectangle([(194, 160), (214, 180)], fill=DARK_TEAL)
    d.rectangle([(160, 194), (180, 214)], fill=DARK_TEAL)
    d.rectangle([(120, 120), (136, 136)], fill=TEAL)
    d.rectangle([(120, 60), (136, 76)], fill=DARK_TEAL)
    d.rectangle([(60, 120), (76, 136)], fill=DARK_TEAL)
    img.save(f"{ICONS_DIR}/qr.png")

def create_typo_icon():
    img = Image.new('RGBA', (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # Concentric target circles
    d.ellipse([(36, 36), (220, 220)], outline=TEAL, width=8, fill=TEAL_FILL)
    d.ellipse([(76, 76), (180, 180)], outline=DARK_TEAL, width=6)
    d.ellipse([(112, 112), (144, 144)], fill=CORAL)
    # Crosshairs
    d.line([(128, 20), (128, 60)], fill=TEAL, width=6)
    d.line([(128, 196), (128, 236)], fill=TEAL, width=6)
    d.line([(20, 128), (60, 128)], fill=TEAL, width=6)
    d.line([(196, 128), (236, 128)], fill=TEAL, width=6)
    img.save(f"{ICONS_DIR}/typo.png")

def create_dashboard_icon():
    img = Image.new('RGBA', (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # Monitor screen
    d.rounded_rectangle([(38, 46), (218, 174)], radius=12, outline=DARK_TEAL, width=8, fill=WHITE)
    # Monitor stand
    d.rectangle([(116, 174), (140, 206)], fill=DARK_TEAL)
    d.rounded_rectangle([(84, 206), (172, 222)], radius=4, fill=DARK_TEAL)
    # Mini chart lines inside
    d.line([(58, 140), (96, 110), (136, 130), (174, 80), (198, 98)], fill=TEAL, width=6)
    d.rectangle([(58, 66), (100, 84)], fill=TEAL_FILL, outline=TEAL, width=2)
    img.save(f"{ICONS_DIR}/dashboard.png")

def create_prooftree_icon():
    img = Image.new('RGBA', (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # Visual DAG network
    nodes = [(60, 60), (60, 196), (140, 128), (216, 128)]
    # Edges
    d.line([nodes[0], nodes[2]], fill=TEAL, width=6)
    d.line([nodes[1], nodes[2]], fill=TEAL, width=6)
    d.line([nodes[2], nodes[3]], fill=CORAL, width=8)
    # Nodes
    for x, y in nodes[:2]:
        d.ellipse([(x-20, y-20), (x+20, y+20)], fill=WHITE, outline=TEAL, width=6)
    d.ellipse([(nodes[2][0]-22, nodes[2][1]-22), (nodes[2][0]+22, nodes[2][1]+22)], fill=TEAL, outline=DARK_TEAL, width=6)
    d.ellipse([(nodes[3][0]-24, nodes[3][1]-24), (nodes[3][0]+24, nodes[3][1]+24)], fill=CORAL, outline=DARK_TEAL, width=6)
    img.save(f"{ICONS_DIR}/prooftree.png")

def create_check_icon():
    img = Image.new('RGBA', (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse([(36, 36), (220, 220)], fill=(91, 185, 139, 40), outline=GREEN, width=8)
    d.line([(80, 128), (114, 162), (180, 96)], fill=GREEN, width=12)
    img.save(f"{ICONS_DIR}/check.png")

def create_astar_diagram():
    """Generates high-res diagram showing A* heuristic pathfinding on strings"""
    w, h = 960, 480
    img = Image.new('RGBA', (w, h), WHITE)
    d = ImageDraw.Draw(img)
    
    # Outer border
    d.rounded_rectangle([(8, 8), (w-8, h-8)], radius=16, outline=BORDER_GRAY, width=4)
    
    font_title = get_font(22, bold=True)
    font_bold = get_font(16, bold=True)
    font_mono = get_font(18, bold=True)
    font_text = get_font(14, bold=False)
    
    # Header badge
    d.text((36, 28), "A* STRING-EDIT PATHFINDING TRACE:  f(n) = g(n) + h(n)", fill=DARK_TEAL, font=font_title)
    d.text((36, 62), "Comparing Candidate Domain 'paypa1' vs Authentic Brand 'paypal' in State Space", fill=TEAL, font=font_bold)
    
    # States table / flow
    steps = [
        {"state": "(0, 0)", "src_char": "'p'", "tgt_char": "'p'", "action": "Exact Match", "g": "0", "h": "0", "f": "0", "color": GREEN},
        {"state": "(1, 1)", "src_char": "'a'", "tgt_char": "'a'", "action": "Exact Match", "g": "0", "h": "0", "f": "0", "color": GREEN},
        {"state": "(2, 2)", "src_char": "'y'", "tgt_char": "'y'", "action": "Exact Match", "g": "0", "h": "0", "f": "0", "color": GREEN},
        {"state": "(3, 3)", "src_char": "'p'", "tgt_char": "'p'", "action": "Exact Match", "g": "0", "h": "0", "f": "0", "color": GREEN},
        {"state": "(4, 4)", "src_char": "'a'", "tgt_char": "'a'", "action": "Exact Match", "g": "0", "h": "0", "f": "0", "color": GREEN},
        {"state": "(5, 5)", "src_char": "'1'", "tgt_char": "'l'", "action": "Substitute (1 -> l)", "g": "1", "h": "0", "f": "1", "color": CORAL},
    ]
    
    col_x = [36, 170, 310, 480, 680, 770, 860]
    headers = ["State (i, j)", "Src Char", "Tgt Brand", "A* Transition", "Cost g(n)", "Heur h(n)", "Total f(n)"]
    
    # Table header bar
    d.rounded_rectangle([(30, 98), (w-30, 134)], radius=6, fill=BG_LIGHT)
    for idx, (hx, header) in enumerate(zip(col_x, headers)):
        d.text((hx, 106), header, fill=DARK_TEAL, font=font_bold)
        
    y_pos = 148
    for item in steps:
        # row highlight for substitution
        if item["g"] == "1":
            d.rounded_rectangle([(30, y_pos-6), (w-30, y_pos+32)], radius=6, fill=(255, 107, 87, 25), outline=CORAL, width=2)
        else:
            d.line([(30, y_pos+30), (w-30, y_pos+30)], fill=(230, 240, 238), width=1)
            
        d.text((col_x[0], y_pos), item["state"], fill=DARK_TEAL, font=font_mono)
        d.text((col_x[1], y_pos), item["src_char"], fill=DARK_TEAL, font=font_mono)
        d.text((col_x[2], y_pos), item["tgt_char"], fill=DARK_TEAL, font=font_mono)
        d.text((col_x[3], y_pos), item["action"], fill=item["color"], font=font_bold)
        d.text((col_x[4], y_pos), item["g"], fill=DARK_TEAL, font=font_mono)
        d.text((col_x[5], y_pos), item["h"], fill=DARK_TEAL, font=font_mono)
        d.text((col_x[6], y_pos), item["f"], fill=item["color"], font=font_bold)
        y_pos += 44

    # Bottom summary callout card
    d.rounded_rectangle([(30, y_pos+16), (w-30, h-24)], radius=8, fill=BG_LIGHT, outline=TEAL, width=2)
    d.text((50, y_pos+26), "A* OPTIMAL RESULT: Exact Edit Distance = 1 (Substitution '1' -> 'l')", fill=DARK_TEAL, font=font_bold)
    d.text((50, y_pos+54), "1 <= distance <= 2 is within typosquatting threshold -> ASSERTS: brand_typosquatting_detected ('paypal')", fill=CORAL, font=font_bold)
    d.text((50, y_pos+82), "Guaranteed Optimal: Admissible heuristic h(i, j) = ||source|-i - |target|-j| never overestimates remaining edits.", fill=TEXT_DARK, font=font_text)
    
    img.save(f"{ICONS_DIR}/astar_diagram.png")

def create_prooftree_diagram():
    """Generates high-res visual proof tree DAG diagram"""
    w, h = 960, 480
    img = Image.new('RGBA', (w, h), WHITE)
    d = ImageDraw.Draw(img)
    
    d.rounded_rectangle([(8, 8), (w-8, h-8)], radius=16, outline=BORDER_GRAY, width=4)
    
    font_title = get_font(22, bold=True)
    font_bold = get_font(15, bold=True)
    font_small = get_font(13, bold=False)
    
    d.text((36, 26), "PROPOSITIONAL FORWARD-CHAINING DERIVATION DAG (PROOF TREE)", fill=DARK_TEAL, font=font_title)
    d.text((36, 58), "Target URL: http://paypa1.com@192.168.1.1:8080/secure/login.exe", fill=CORAL, font=font_bold)
    
    # 3 Layers: Observable Facts (Left) -> Inferred Horn Clauses (Center) -> Verdict (Right)
    
    # Layer Headers
    d.text((40, 94), "OBSERVABLE FACTS (LEXICAL)", fill=TEAL, font=font_bold)
    d.text((360, 94), "HORN CLAUSE DEDUCTIONS (RULES)", fill=TEAL, font=font_bold)
    d.text((710, 94), "FINAL CATEGORICAL VERDICT", fill=TEAL, font=font_bold)
    
    facts = [
        {"name": "host_is_raw_ip", "sub": "Host is 192.168.1.1", "y": 130},
        {"name": "userinfo_embedded", "sub": "Masked via paypa1.com@", "y": 200},
        {"name": "typosquat_paypal", "sub": "A* edit distance = 1", "y": 270},
        {"name": "dangerous_extension", "sub": "Executable file .exe", "y": 340},
        {"name": "non_standard_port", "sub": "HTTP port 8080", "y": 410},
    ]
    
    rules = [
        {"name": "RULE 14: HOST DECEPTION", "sub": "raw_ip & userinfo -> host_masking", "y": 165},
        {"name": "RULE 22: BRAND PHISHING", "sub": "typosquat & raw_ip -> credential_theft", "y": 270},
        {"name": "RULE 31: MALWARE DELIVERY", "sub": "dangerous_ext -> executable_payload", "y": 375},
    ]
    
    # Draw connectors first
    # Fact 0 & 1 -> Rule 0
    d.line([(280, 150), (350, 185)], fill=TEAL, width=3)
    d.line([(280, 220), (350, 185)], fill=TEAL, width=3)
    # Fact 0 & 2 -> Rule 1
    d.line([(280, 150), (350, 290)], fill=TEAL, width=3)
    d.line([(280, 290), (350, 290)], fill=TEAL, width=3)
    # Fact 3 -> Rule 2
    d.line([(280, 360), (350, 395)], fill=TEAL, width=3)
    
    # Rules -> Final Verdict
    d.line([(640, 185), (710, 280)], fill=CORAL, width=4)
    d.line([(640, 290), (710, 280)], fill=CORAL, width=4)
    d.line([(640, 395), (710, 280)], fill=CORAL, width=4)
    
    # Draw Fact Cards
    for f in facts:
        d.rounded_rectangle([(40, f["y"]), (280, f["y"]+50)], radius=8, fill=BG_LIGHT, outline=TEAL, width=2)
        d.text((52, f["y"]+6), f["name"], fill=DARK_TEAL, font=font_bold)
        d.text((52, f["y"]+28), f["sub"], fill=TEXT_DARK, font=font_small)
        
    # Draw Rule Cards
    for r in rules:
        d.rounded_rectangle([(350, r["y"]), (640, r["y"]+54)], radius=8, fill=WHITE, outline=DARK_TEAL, width=2)
        d.text((362, r["y"]+6), r["name"], fill=DARK_TEAL, font=font_bold)
        d.text((362, r["y"]+30), r["sub"], fill=TEAL, font=font_small)
        
    # Draw Final Verdict Card
    d.rounded_rectangle([(710, 210), (920, 350)], radius=12, fill=(255, 107, 87, 30), outline=CORAL, width=4)
    d.text((740, 230), "VERDICT:", fill=CORAL, font=font_bold)
    font_huge = get_font(28, bold=True)
    d.text((735, 260), "HIGH RISK", fill=CORAL, font=font_huge)
    d.text((726, 305), "Proven via 3 Horn Rules", fill=DARK_TEAL, font=font_small)
    d.text((724, 324), "100% Deterministic Proof", fill=DARK_TEAL, font=font_small)
    
    img.save(f"{ICONS_DIR}/prooftree_diagram.png")

def generate_all_assets():
    create_shield_icon()
    create_alert_icon()
    create_parser_icon()
    create_search_icon()
    create_logic_icon()
    create_qr_icon()
    create_typo_icon()
    create_dashboard_icon()
    create_prooftree_icon()
    create_check_icon()
    create_astar_diagram()
    create_prooftree_diagram()
    print("All icons and diagrams generated successfully in", ICONS_DIR)

if __name__ == "__main__":
    generate_all_assets()
