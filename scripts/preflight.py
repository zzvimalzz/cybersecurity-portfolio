#!/usr/bin/env python3
import ipaddress
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SELF = Path(__file__).resolve()
TODO = "TODO(vimal)"
TEXT_SUFFIXES = {".md", ".yml", ".yaml", ".html", ".css", ".js", ".json", ".txt", ".xml", ".py", ".svg", ".rb", ".gitignore"}
LOCAL_ONLY_PREFIXES = ("doc/", ".agents/", ".codex/")
LOCAL_ONLY_FILES = ("AGENTS.md", "skills-lock.json")
PROJECT_HEADINGS = [
    "Objective",
    "Environment and tools",
    "Method",
    "Results",
    "What I would do differently",
]
FRONT_MATTER_KEYS = ["layout", "title", "permalink", "order", "summary", "tools", "skills"]
WORD_LIMITS = {
    "about": (100, 200),
    "journey": (400, 600),
    "career": (100, 200),
}
BANNED = [
    r"passionate", r"leverage", r"delve", r"robust", r"seamless", r"cutting-edge",
    r"dynamic", r"innovative", r"comprehensive", r"ever-evolving", r"in today's digital world",
    r"unlock", r"empower", r"elevate", r"showcase", r"dive into", r"game-changer",
    r"at the intersection of", r"firm believer", r"not only .{1,80} but also",
    r"it'?s not just .{1,80}, it'?s",
]
EXCLAMATION = re.compile(r"(?<=[\w)])!(?=\s|$)")
SECRET_PATTERNS = {
    "private key header": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "password assignment": re.compile(r"password\s*[:=]", re.I),
    "api key": re.compile(r"api[_-]?key", re.I),
    "AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "flag": re.compile(r"FLAG\{"),
    "Malaysian mobile number": re.compile(r"\+?60\s?1\d[\s-]?\d{3,4}[\s-]?\d{4}"),
}
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
GITHUB_NOREPLY = re.compile(r"@users\.noreply\.github\.com$")

failures = []
pending = []
notes = []


def git_files(*args):
    out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines() if line]


def candidate_files():
    tracked = git_files("ls-files")
    untracked = git_files("ls-files", "--others", "--exclude-standard")
    return sorted(set(tracked) | set(untracked)), tracked


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8", errors="replace")


def is_text(rel):
    return Path(rel).suffix.lower() in TEXT_SUFFIXES


def front_matter(text):
    match = re.match(r"---\r?\n(.*?)\r?\n---", text, re.S)
    return match.group(1) if match else ""


def word_count(text):
    text = re.sub(r"<!--.*?-->", " ", text, flags=re.S)
    text = re.sub(r"[#*_`>]", " ", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    return len(text.split())


def check_todo(files):
    for rel in files:
        if rel.replace("\\", "/") == "scripts/preflight.py" or not is_text(rel):
            continue
        if rel == "README.md":
            continue
        count = read(rel).count(TODO)
        if count:
            pending.append(f"{rel}: {count} {TODO} marker(s)")


def top_section(text, key):
    match = re.search(rf"^{key}:\n((?:[ \t]+.*\n|\n)*)", text, re.M)
    return match.group(1) if match else ""


def block(text, key):
    match = re.search(rf"^( *){key}: \|\n((?:\1 +.*\n|\n)*)", text, re.M)
    return "\n".join(line.strip() for line in match.group(2).splitlines()) if match else ""


def section_texts():
    data = read("_data/site.yml")
    career = top_section(data, "career")
    steps = career.split("steps:", 1)[1].split("path:", 1)[0] if "steps:" in career else ""
    step_lines = [m.strip() for m in re.findall(r"^\s+- (.+)$", steps, re.M)]
    journey = top_section(data, "journey")
    bodies = [block(item, "body") for item in re.split(r"^  - title:", journey, flags=re.M)[1:]]
    return {
        "about": block(data, "about"),
        "journey": "\n".join(bodies),
        "career": block(career, "statement") + "\n" + "\n".join(step_lines),
    }


def check_word_counts(files):
    if not (ROOT / "_data/site.yml").exists():
        failures.append("_data/site.yml: missing")
        return
    for name, text in section_texts().items():
        low, high = WORD_LIMITS[name]
        count = word_count(text)
        label = f"_data/site.yml {name}: {count} words (need {low} to {high})"
        if TODO in text:
            pending.append(f"{label}, still has {TODO}")
        elif not low <= count <= high:
            failures.append(label)
        else:
            notes.append(label)


def check_projects(files):
    project_dirs = sorted({Path(f).parts[1] for f in files if f.startswith("projects/") and len(Path(f).parts) > 2})
    if len(project_dirs) < 2:
        failures.append(f"projects/: need at least 2 project folders, found {len(project_dirs)}")
    for slug in project_dirs:
        readme = f"projects/{slug}/README.md"
        if not (ROOT / readme).exists():
            failures.append(f"{readme}: missing")
            continue
        text = read(readme)
        has_todo = TODO in text
        report = pending if has_todo else failures

        fm = front_matter(text)
        for key in FRONT_MATTER_KEYS:
            if not re.search(rf"^{key}:", fm, re.M):
                failures.append(f"{readme}: front matter key `{key}` missing")
        summary = re.search(r"^summary:\s*(.+)$", fm, re.M)
        if summary and len(summary.group(1).strip()) >= 70:
            failures.append(f"{readme}: summary is {len(summary.group(1).strip())} characters (limit 69)")

        body = text.split("\n---", 1)[1] if text.startswith("---") else text
        headings = re.findall(r"^## (.+?)\s*$", body, re.M)
        if headings[: len(PROJECT_HEADINGS)] != PROJECT_HEADINGS:
            failures.append(f"{readme}: headings are {headings}, expected {PROJECT_HEADINGS}")
        if re.search(r"Back to portfolio", body):
            failures.append(f"{readme}: remove the 'Back to portfolio' link; the layout provides navigation")

        linked = set(re.findall(r"\]\((?:\./)?evidence/([^)#\s]+)", text))
        evidence_dir = ROOT / "projects" / slug / "evidence"
        on_disk = {p.name for p in evidence_dir.glob("*") if p.is_file() and not p.name.startswith(".")} if evidence_dir.exists() else set()
        if not linked:
            report.append(f"{readme}: no link into evidence/")
        for name in sorted(on_disk - linked):
            report.append(f"{readme}: evidence/{name} is not linked")
        for name in sorted(linked - on_disk):
            failures.append(f"{readme}: links to evidence/{name}, which does not exist")


def check_skill_links(files):
    skills_path = ROOT / "_data/skills.yml"
    if not skills_path.exists():
        failures.append("_data/skills.yml: missing")
        return
    skills_text = skills_path.read_text(encoding="utf-8")
    skill_ids = set(re.findall(r"^\s*- id:\s*(\S+)", skills_text, re.M))
    slugs = {Path(f).parts[1] for f in files if f.startswith("projects/") and len(Path(f).parts) > 2}

    for evidence in re.findall(r"^\s+evidence:\s*\[(.*?)\]", skills_text, re.M):
        for slug in [s.strip() for s in evidence.split(",") if s.strip()]:
            if slug not in slugs:
                failures.append(f"_data/skills.yml: evidence `{slug}` is not a project folder")

    for slug in sorted(slugs):
        readme = ROOT / "projects" / slug / "README.md"
        if not readme.exists():
            continue
        match = re.search(r"^skills:\s*\[(.*?)\]", front_matter(readme.read_text(encoding="utf-8")), re.M)
        for skill in [s.strip() for s in (match.group(1) if match else "").split(",") if s.strip()]:
            if skill not in skill_ids:
                failures.append(f"projects/{slug}/README.md: skill `{skill}` is not in _data/skills.yml")


def allowed_email():
    site = ROOT / "_data/site.yml"
    if site.exists():
        match = re.search(r"^  email:\s*(\S+)", site.read_text(encoding="utf-8"), re.M)
        if match:
            return match.group(1).strip().strip("\"'")
    return None


def check_patterns(files):
    allowed = allowed_email()
    for rel in files:
        if (ROOT / rel).resolve() == SELF or not is_text(rel):
            continue
        if rel.endswith(".css"):
            continue
        text = read(rel)
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                failures.append(f"{rel}: matches {label}")
        for raw in [] if rel.endswith(".svg") or "/tests/" in rel else IPV4.findall(text):
            try:
                ip = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if not (ip.is_private or ip.is_loopback or ip.is_unspecified):
                failures.append(f"{rel}: public-looking IPv4 address {raw}")
        for email in EMAIL.findall(text):
            if email == allowed or GITHUB_NOREPLY.search(email):
                continue
            failures.append(f"{rel}: email address {email} is not the one in _data/site.yml")


def check_banned(files):
    scope = [
        f for f in files
        if (f.startswith("_data/") or re.match(r"projects/[^/]+/README\.md$", f))
        and is_text(f)
    ]
    for rel in scope:
        text = read(rel)
        for pattern in BANNED:
            for match in re.finditer(pattern, text, re.I):
                failures.append(f"{rel}: banned phrase `{match.group(0)}`")
        if rel.endswith(".md") and EXCLAMATION.search(text):
            failures.append(f"{rel}: exclamation mark")


def check_local_only(tracked):
    for rel in tracked:
        if rel.startswith(LOCAL_ONLY_PREFIXES) or rel in LOCAL_ONLY_FILES:
            failures.append(f"{rel}: local-only file is tracked by git")


def main():
    final = "--final" in sys.argv[1:]
    files, tracked = candidate_files()
    files = [f for f in files if (ROOT / f).is_file()]
    check_todo(files)
    check_word_counts(files)
    check_projects(files)
    check_skill_links(files)
    check_patterns(files)
    check_banned(files)
    check_local_only(tracked)

    for line in notes:
        print(f"ok       {line}")
    for line in pending:
        print(f"pending  {line}")
    for line in failures:
        print(f"FAIL     {line}")

    problems = len(failures) + (len(pending) if final else 0)
    print(f"\n{len(failures)} failure(s), {len(pending)} pending owner item(s){' (counted as failures: --final)' if final else ''}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
