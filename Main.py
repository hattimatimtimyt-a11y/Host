#!/usr/bin/env python3
"""
Security scanner for uploaded Telegram bot code.

Fixed issues from previous version:
  • Missing closing brace on WEIGHTS (now MAX_CATEGORY_SCORE dict)
  • Per-pattern weights -> os.walk('/root') alone no longer auto-rejects
  • cred_only branch no longer loses the token warning
  • tar extraction now path-checked (previously ZIP-slip only)
  • ZIP-slip check now uses realpath (previously naive '..' substring)
  • Alias-aware AST scan (import os as o; o.walk(...))
  • Raw-string prefixes (os.walk(r'/root')) now handled
  • Scan .pyc/.pyo/.js/.ts correctly (no reading binary as text)
  • Archive scan aggregates findings across all files, not just worst
  • Unused IP_RE removed; redundant verdict branches merged
"""

import os
import re
import ast
import zipfile
import tarfile
import tempfile
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════
#  PATTERNS — (regex, description, weight)
#  Per-pattern weights let us rank severity. Soft signals like
#  arcname=os.path.relpath no longer trigger a REJECT on their own.
# ═══════════════════════════════════════════════════════════════

PATTERNS: Dict[str, List[Tuple[str, str, int]]] = {

    "🔴 Data Theft": [
        # --- HARD signals (strong evidence of exfiltration) ---
        (r'os\.walk\s*\(\s*[rR]?["\'][/\\](?:root|etc|proc|sys|home|var)\b',
            "os.walk on server directory", 22),
        (r'send_document\s*\([^\n]*open\s*\(\s*[rR]?["\'][/\\](?:root|etc|proc|sys)',
            "System file sent via Telegram", 30),
        (r'glob\.glob\s*\(\s*[rR]?["\'][/\\]\*',
            "Root glob scan", 20),
        (r'shutil\.(?:copy|copy2|copyfile)\s*\([^\n]*/root',
            "Copying from /root", 25),
        (r'ROOT_DIR\s*=\s*[rR]?["\'][/\\]["\']',
            "Targeting root directory", 22),
        (r'post_init\s*=.*send_document|send_document.*post_init',
            "Auto-send file at startup", 20),
        # --- SOFT signals (suspicious but often legitimate) ---
        (r'\bbackup_log\b',
            "backup_log reference", 8),
        (r'arcname\s*=\s*os\.path\.relpath',
            "Packing with relative arcname", 8),
    ],

    "🔴 Backdoor": [
        (r'os\.system\s*\(\s*[^\)]{3,}\)',
            "os.system() shell execution", 25),
        (r'subprocess\s*\.\s*(?:Popen|call|run)\s*\([^\n]*shell\s*=\s*True[^\n]*(?:input|stdin)',
            "Shell injection via subprocess", 30),
        (r'marshal\.loads\s*\(',
            "marshal.loads() bytecode", 30),
        (r'ADMINNAME\s*=\s*["\'][^"\']{1,50}["\']',
            "Hardcoded secret admin word", 15),
        (r'#.*(?:LEGITIMATE LAGTA HAI|dikhta aisa hai)',
            "Deceptive comment", 10),
    ],

    "🟠 Hidden Bot": [
        (r'\binfinity_polling\s*\(',                 "infinity_polling",       3),
        (r'\brun_polling\s*\(',                      "run_polling",            3),
        (r'\bbot\.polling\s*\(',                     "bot.polling",            3),
        (r'\bupdater\.start_polling\s*\(',           "updater.start_polling",  3),
        (r'Application\.builder\s*\(\s*\)',          "Application.builder()",  3),
        (r'\btelebot\.TeleBot\s*\(',                 "telebot.TeleBot()",      3),
        (r'\bBot\s*\(\s*token\s*=',                  "Bot(token=...)",         3),
        (r'\bCommandHandler\s*\(',                   "CommandHandler",         2),
        (r'\bMessageHandler\s*\(',                   "MessageHandler",         2),
        (r'\b(?:hosting_bot|host_bot|panel_bot)\b',  "Nested hosting service", 5),
    ],

    "🟡 Suspicious Network": [
        (r'devil-api\.com|elementfx\.io',
            "Known malicious endpoint", 25),
        (r'open\s*\(\s*[rR]?["\'][/\\](?:root|etc|proc|sys)[^\)]*\)[^\n]*(?:requests|urllib)',
            "System file read + HTTP POST", 30),
        (r'pastebin\.com/raw',
            "Pastebin raw fetch", 25),
        (r'bit\.ly/|tinyurl\.com/',
            "Shortened URL", 8),
        (r'\b(?:ngrok|localtunnel|serveo\.net)\b',
            "Tunnel service", 12),
        (r'requests\.post\s*\([^\n]*token[^\n]*\)',
            "Token POSTed externally", 25),
    ],

    "🟡 Obfuscation": [
        (r'base64\.b64decode\s*\([^\n]+\)[^\n]*\bexec\b',
            "Base64 decode + exec", 30),
        (r'zlib\.decompress\s*\([^\n]+\)[^\n]*\bexec\b',
            "Compressed code + exec", 30),
        (r'(?:\\x[0-9a-fA-F]{2}){6,}',
            "Long hex string", 12),
        (r'chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(\s*\d+\s*\)',
            "chr() chain", 8),
    ],

    "🟠 Resource Abuse": [
        (r'multiprocessing\.Pool\s*\(\s*(?:None|\d{3,})',
            "Massive process pool", 18),
        (r'fork\s*\(\s*\)\s*[;\n].*fork\s*\(\s*\)',
            "Fork bomb", 30),
        (r'while\s+True\s*:[^\n]*threading\.Thread',
            "Loop + threading", 15),
    ],
}


# Per-category score cap: many weak hits in one category cannot
# alone dominate the total score.
MAX_CATEGORY_SCORE: Dict[str, int] = {
    "🔴 Data Theft":          60,
    "🔴 Backdoor":            60,
    "🔴 Exposed Credentials": 15,
    "🟠 Hidden Bot":          10,
    "🟠 Resource Abuse":      25,
    "🟡 Suspicious Network":  30,
    "🟡 Obfuscation":         30,
}

BLOCKING_CATEGORIES = ("🔴 Data Theft", "🔴 Backdoor")


# Telegram tokens: 8-10 digits, colon, 30-40 base64-ish chars.
BOT_TOKEN_RE = re.compile(r'\b\d{8,10}:[A-Za-z0-9_-]{30,40}\b')


# ═══════════════════════════════════════════════════════════════
#  STATIC PATTERN SCAN
# ═══════════════════════════════════════════════════════════════

def static_scan(code: str) -> Tuple[Dict[str, List[str]], Dict[str, int]]:
    """Regex scan. Returns (findings_by_category, score_by_category)."""
    findings: Dict[str, List[str]] = {}
    scores: Dict[str, int] = {}

    for category, pattern_list in PATTERNS.items():
        hits: List[str] = []
        cat_score = 0
        for pattern, description, weight in pattern_list:
            if re.search(pattern, code, re.MULTILINE):
                hits.append(description)
                cat_score += weight
        if hits:
            findings[category] = hits
            cap = MAX_CATEGORY_SCORE.get(category, 20)
            scores[category] = min(cat_score, cap)

    tokens = BOT_TOKEN_RE.findall(code)
    if tokens:
        findings.setdefault("🔴 Exposed Credentials", [])
        findings["🔴 Exposed Credentials"].append(
            f"Hardcoded Bot Token: {tokens[0][:15]}… "
            f"({len(tokens)} token(s) found)"
        )
        scores["🔴 Exposed Credentials"] = MAX_CATEGORY_SCORE["🔴 Exposed Credentials"]

    return findings, scores


# ═══════════════════════════════════════════════════════════════
#  AST DEEP SCAN
#  Handles import aliases and evaluates string literals correctly.
# ═══════════════════════════════════════════════════════════════

_SENSITIVE_WALK_DIRS = {"/", "/root", "/etc", "/home", "/proc", "/var", "/sys"}
_SENSITIVE_PATH_LITERALS = {
    "/etc/passwd", "/etc/shadow",
    "/root/.ssh", "/root/.bash_history", "/etc/ssh",
}
_BAD_CLASS_WORDS = {
    "harvest", "steal", "exfil", "harvester",
    "collector", "grabber", "stealer",
}


def ast_scan(code: str) -> List[str]:
    findings: List[str] = []
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        findings.append(f"Cannot parse: {e} — possibly obfuscated")
        return findings

    # Collect aliases for `os` and `os.walk`
    os_names = {"os"}
    walk_names = {"walk"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "os":
                    os_names.add(a.asname or "os")
        elif isinstance(node, ast.ImportFrom) and node.module == "os":
            for a in node.names:
                if a.name == "walk":
                    walk_names.add(a.asname or "walk")

    for node in ast.walk(tree):

        if isinstance(node, ast.Call):
            func = node.func

            # --- os.walk('<sensitive>') ---
            target_arg: Optional[ast.AST] = None
            if isinstance(func, ast.Attribute) and func.attr in walk_names:
                if isinstance(func.value, ast.Name) and func.value.id in os_names:
                    target_arg = node.args[0] if node.args else None
            elif isinstance(func, ast.Name) and func.id in walk_names:
                target_arg = node.args[0] if node.args else None

            if (target_arg is not None
                    and isinstance(target_arg, ast.Constant)
                    and isinstance(target_arg.value, str)
                    and target_arg.value in _SENSITIVE_WALK_DIRS):
                findings.append(
                    f"os.walk('{target_arg.value}') — sensitive directory scan"
                )

            # --- eval/exec/compile/__import__ (any argument) ---
            if isinstance(func, ast.Name):
                if func.id in ("eval", "exec", "compile") and node.args:
                    findings.append(
                        f"Dangerous: {func.id}() — dynamic code execution"
                    )
                if func.id == "__import__" and node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant):
                        findings.append(f"Dangerous: __import__({arg.value!r})")
                    else:
                        findings.append("Dangerous: dynamic __import__()")

        # --- Suspicious class names ---
        if isinstance(node, ast.ClassDef):
            low = node.name.lower()
            if any(b in low for b in _BAD_CLASS_WORDS):
                findings.append(f"Suspicious class name: {node.name}")

        # --- Literal sensitive paths (not over-broad like '/home') ---
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value in _SENSITIVE_PATH_LITERALS:
                findings.append(f"Hardcoded sensitive path: {node.value!r}")

    return findings


# ═══════════════════════════════════════════════════════════════
#  RISK & VERDICT
# ═══════════════════════════════════════════════════════════════

def calculate_risk(scores: Dict[str, int], ast_findings: List[str]) -> int:
    total = sum(scores.values())
    unique_ast = list(dict.fromkeys(ast_findings))
    total += min(len(unique_ast) * 5, 20)
    return min(total, 100)


def get_verdict(risk: int,
                findings: Dict[str, List[str]]) -> Tuple[str, str]:
    has_blocking = any(findings.get(c) for c in BLOCKING_CATEGORIES)
    has_creds    = "🔴 Exposed Credentials" in findings

    if risk >= 70:
        return "DANGEROUS", "REJECT"
    if risk >= 55 and has_blocking:
        return "DANGEROUS", "REJECT"
    if risk >= 30:
        return "SUSPICIOUS", "MANUAL_REVIEW"
    if has_creds:                     # low risk but token present -> warn, allow
        return "SUSPICIOUS", "APPROVE"
    return "SAFE", "APPROVE"


# ═══════════════════════════════════════════════════════════════
#  CORE CODE SCANNER
# ═══════════════════════════════════════════════════════════════

def scan_code(code: str, filename: str = "file.py") -> Dict[str, Any]:
    findings, scores = static_scan(code)
    ast_findings = ast_scan(code)
    risk = calculate_risk(scores, ast_findings)
    verdict, recommendation = get_verdict(risk, findings)

    all_threats: List[str] = [
        f"{c}: {h}" for c, hits in findings.items() for h in hits
    ] + ast_findings

    if verdict == "DANGEROUS":
        summary = f"⚠️ File DANGEROUS hai! {len(all_threats)} threat(s) mili hain."
    elif verdict == "SUSPICIOUS":
        summary = "🔍 File suspicious hai. Admin se manual review karwao."
    else:
        summary = "✅ File safe lagti hai. Koi major threat nahi mila."

    return {
        "verdict":        verdict,
        "risk_score":     risk,
        "findings":       findings,
        "ast_findings":   ast_findings,
        "all_threats":    all_threats,
        "recommendation": recommendation,
        "summary":        summary,
        "filename":       filename,
    }


# ═══════════════════════════════════════════════════════════════
#  ARCHIVE SCANNER  (ZIP / tar) — with real path-traversal checks
# ═══════════════════════════════════════════════════════════════

def _inside(dest_real: str, target: str) -> bool:
    """True if `target` (resolved) is `dest` or strictly below it."""
    return target == dest_real or target.startswith(dest_real + os.sep)


def _safe_extract_zip(z: zipfile.ZipFile, dest: str) -> None:
    dest_real = os.path.realpath(dest)
    for name in z.namelist():
        target = os.path.realpath(os.path.join(dest_real, name))
        if not _inside(dest_real, target):
            raise ValueError(f"Unsafe path in ZIP: {name!r}")
    z.extractall(dest)


def _safe_extract_tar(t: tarfile.TarFile, dest: str) -> None:
    dest_real = os.path.realpath(dest)
    for member in t.getmembers():
        target = os.path.realpath(os.path.join(dest_real, member.name))
        if not _inside(dest_real, target):
            raise ValueError(f"Unsafe path in tar: {member.name!r}")
        if member.issym() or member.islnk():
            link_target = os.path.realpath(
                os.path.join(dest_real, member.linkname)
            )
            if not _inside(dest_real, link_target):
                raise ValueError(
                    f"Unsafe link in tar: {member.name!r} -> {member.linkname!r}"
                )
    # Python 3.12+ has filter='data'; else our manual checks above suffice.
    try:
        t.extractall(dest, filter="data")
    except TypeError:
        t.extractall(dest)


def _archive_reject(filename: str, reason: str) -> Dict[str, Any]:
    return {
        "verdict":        "DANGEROUS",
        "risk_score":     99,
        "findings":       {"🔴 Zip Slip / Path Traversal": [reason]},
        "ast_findings":   [],
        "all_threats":    [reason],
        "recommendation": "REJECT",
        "summary":        "Unsafe archive detected!",
        "filename":       filename,
    }


def _archive_review(filename: str, reason: str) -> Dict[str, Any]:
    return {
        "verdict":        "SUSPICIOUS",
        "risk_score":     25,
        "findings":       {"🟡 Warning": [reason]},
        "ast_findings":   [],
        "all_threats":    [reason],
        "recommendation": "MANUAL_REVIEW",
        "summary":        reason,
        "filename":       filename,
    }


def _scan_archive(file_path: str) -> Dict[str, Any]:
    filename = os.path.basename(file_path)
    tmp = tempfile.mkdtemp()
    try:
        try:
            if file_path.endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as z:
                    _safe_extract_zip(z, tmp)
            elif file_path.lower().endswith(('.tar.gz', '.tgz', '.tar')):
                with tarfile.open(file_path, 'r:*') as t:
                    _safe_extract_tar(t, tmp)
            else:
                return _archive_review(filename, "Unknown archive format")
        except (ValueError, zipfile.BadZipFile, tarfile.TarError) as e:
            return _archive_reject(filename, str(e))

        py_files = list(Path(tmp).rglob("*.py"))
        if not py_files:
            return _archive_review(filename, "No .py files found in archive")

        combined_findings: Dict[str, List[str]] = {}
        combined_ast: List[str] = []
        max_risk = 0
        files_with_findings = 0
        scanned = 0

        for py_file in py_files[:30]:
            try:
                code = py_file.read_text(errors='ignore')
            except Exception:
                continue
            result = scan_code(code, py_file.name)
            scanned += 1
            max_risk = max(max_risk, result['risk_score'])
            if result['all_threats']:
                files_with_findings += 1
            for cat, hits in result['findings'].items():
                bucket = combined_findings.setdefault(cat, [])
                for h in hits:
                    if h not in bucket:
                        bucket.append(h)
            for f in result['ast_findings']:
                if f not in combined_ast:
                    combined_ast.append(f)

        if scanned == 0:
            return _archive_review(filename, "No readable .py files in archive")

        # Small bonus if multiple files trigger findings (organized attack)
        if files_with_findings >= 3:
            max_risk = min(max_risk + 10, 100)
        elif files_with_findings >= 2:
            max_risk = min(max_risk + 5, 100)

        verdict, recommendation = get_verdict(max_risk, combined_findings)

        all_threats: List[str] = [
            f"{c}: {h}" for c, hits in combined_findings.items() for h in hits
        ] + combined_ast

        if verdict == "DANGEROUS":
            summary = f"⚠️ Archive DANGEROUS hai! {len(all_threats)} threat(s)."
        elif verdict == "SUSPICIOUS":
            summary = "🔍 Archive suspicious hai. Manual review zaroori."
        else:
            summary = "✅ Archive safe lagti hai."

        return {
            "verdict":        verdict,
            "risk_score":     max_risk,
            "findings":       combined_findings,
            "ast_findings":   combined_ast,
            "all_threats":    all_threats,
            "recommendation": recommendation,
            "summary":        summary,
            "filename":       filename,
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═══════════════════════════════════════════════════════════════

_TEXT_EXTS = ('.py', '.pyw')
_BINARY_EXTS = ('.pyc', '.pyo')
_JS_EXTS = ('.js', '.ts', '.jsx', '.tsx')


def scan_file(file_path: str) -> Dict[str, Any]:
    """
    Scan any uploaded file before saving / approving it.

    Usage:
        from security_scanner_free import scan_file
        result = scan_file("/tmp/uploaded_bot.py")
        rec    = result["recommendation"]   # APPROVE / MANUAL_REVIEW / REJECT
    """
    filename = os.path.basename(file_path)
    lower = filename.lower()

    try:
        # 1) Archives
        if lower.endswith(('.zip', '.tar.gz', '.tgz', '.tar')):
            return _scan_archive(file_path)

        # 2) Python source
        if lower.endswith(_TEXT_EXTS):
            with open(file_path, 'r', errors='ignore') as fh:
                return scan_code(fh.read(), filename)

        # 3) Compiled Python (cannot AST-parse reliably)
        if lower.endswith(_BINARY_EXTS):
            return _archive_review(
                filename,
                f"Compiled Python ({lower.rsplit('.', 1)[-1]}) — source not scannable",
            )

        # 4) JavaScript / TypeScript — our patterns are Python-focused
        if lower.endswith(_JS_EXTS):
            return _archive_review(
                filename,
                f"{lower.rsplit('.', 1)[-1].upper()} file — limited scanner support",
            )

        # 5) Everything else
        return _archive_review(filename, f"Unsupported file type: {lower}")

    except Exception as e:
        return {
            "verdict":        "ERROR",
            "risk_score":     50,
            "findings":       {},
            "ast_findings":   [],
            "all_threats":    [f"Scan error: {e}"],
            "recommendation": "MANUAL_REVIEW",
            "summary":        f"Scan error: {e}",
            "filename":       filename,
        }


# ═══════════════════════════════════════════════════════════════
#  DEMO / SELF-TEST
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    _tests = [
        ("Data Theft Bot (should REJECT)", """
import os, zipfile, tempfile
from telegram.ext import Application, CommandHandler

BOT_TOKEN = "8969205912:AAHacz7sK01SGUVRndasANl9k-bQKDrw4ic"
ROOT_DIR = "/"

def create_py_zip():
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk('/root'):
            for file in files:
                z.write(os.path.join(root, file))
    return tmp.name

app = Application.builder().token(BOT_TOKEN).build()
app.run_polling()
"""),
        ("Normal Telegram Bot (should APPROVE)", """
import telebot
bot = telebot.TeleBot("YOUR_TOKEN_HERE")

@bot.message_handler(commands=["start"])
def start(message):
    bot.reply_to(message, "Hello!")

bot.infinity_polling()
"""),
        ("Legit backup bot w/ arcname (should APPROVE)", """
import os, zipfile, shutil

def backup():
    with zipfile.ZipFile("backup.zip", "w") as z:
        for root, _, files in os.walk("data"):
            for f in files:
                p = os.path.join(root, f)
                z.write(p, arcname=os.path.relpath(p, "data"))
"""),
        ("ptb v20 token-not-hardcoded (should APPROVE)", """
import os
from telegram.ext import ApplicationBuilder, CommandHandler

async def start(update, context):
    await update.message.reply_text("Hi!")

app = ApplicationBuilder().token(os.environ["BOT_TOKEN"]).build()
app.add_handler(CommandHandler("start", start))
app.run_polling()
"""),
        ("Hardcoded token, benign bot (APPROVE w/ warning)", """
import telebot
bot = telebot.TeleBot("8969205912:AAHacz7sK01SGUVRndasANl9k-bQKDrw4ic")
bot.infinity_polling()
"""),
    ]

    for name, code in _tests:
        r = scan_code(code, "test.py")
        icon = {"DANGEROUS": "🔴", "SUSPICIOUS": "🟡",
                "SAFE": "🟢", "ERROR": "⚫"}[r["verdict"]]
        print(f"\n{'━' * 60}")
        print(f"🧪 {name}")
        print(f"{icon} {r['verdict']}  |  risk {r['risk_score']}/100  |  {r['recommendation']}")
        print(f"   {r['summary']}")
        for t in r["all_threats"][:6]:
            print(f"   • {t}")
    print(f"\n{'━' * 60}")
    print("✅ Scanner ready — `from security_scanner_free import scan_file`")
