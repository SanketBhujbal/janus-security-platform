"""One-shot script: create GitHub repo SanketBhujbal/speedpay-demo,
initialise git in target-dotnet-api, push seeded vulnerable code to main.

Usage:
    python scripts/setup_github_repo.py --token <GITHUB_TOKEN>
    # or set GITHUB_TOKEN env var and run without --token
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO_NAME   = "speedpay-demo"
REPO_OWNER  = "SanketBhujbal"
REPO_SLUG   = f"{REPO_OWNER}/{REPO_NAME}"
DESCRIPTION = "Seeded vulnerable ASP.NET Core payments API for the Agentic Security Platform demo"
TARGET_DIR  = Path(__file__).resolve().parents[1] / "sandbox" / "target-dotnet-api"
GITIGNORE   = """\
bin/
obj/
*.user
.vs/
.security_workdir/
*.original
"""
README = """\
# SpeedPay Demo API

Seeded **vulnerable** ASP.NET Core payments API used by the
[Agentic Security Platform](https://github.com/SanketBhujbal) demo.

## Seeded vulnerabilities (PCI-DSS)

| Endpoint | Vulnerability | Rule |
|---|---|---|
| `POST /api/payments/charge` | PAN + CVV written to logs | `pan-cvv-logging` |
| `POST /api/payments/transfer` | No idempotency-key dedup | `missing-idempotency` |
| `POST /api/webhook/gateway` | Trusts callback amount blindly | `webhook-amount-trust` |

> **DO NOT USE IN PRODUCTION.** This code is intentionally insecure for demo purposes.
"""

def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None) -> None:
    print(f"  $ {' '.join(cmd)}")
    # GIT_SSL_NO_VERIFY bypasses corporate TLS-inspection proxy for git operations.
    merged = {**os.environ, "GIT_SSL_NO_VERIFY": "true", **(env or {})}
    r = subprocess.run(cmd, cwd=cwd or TARGET_DIR,
                       env=merged, check=True,
                       capture_output=True, text=True)
    if r.stdout.strip(): print("   ", r.stdout.strip()[:200])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"))
    args = parser.parse_args()

    if not args.token:
        print("ERROR: --token required or set GITHUB_TOKEN env var")
        sys.exit(1)

    token = args.token

    # ── 1. Create GitHub repo via API ────────────────────────────────────────
    try:
        from github import Github, Auth
        import ssl, urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        print("ERROR: pip install PyGithub"); sys.exit(1)

    # Corporate TLS-inspection proxy has a self-signed cert that Python's
    # bundled certifi store doesn't trust. Disable verification so the
    # GitHub API calls go through (PowerShell works because it uses the
    # Windows cert store; Python uses its own bundle).
    import requests
    original_request = requests.Session.request
    def _no_verify_request(self, method, url, **kwargs):
        kwargs.setdefault("verify", False)
        return original_request(self, method, url, **kwargs)
    requests.Session.request = _no_verify_request

    gh = Github(auth=Auth.Token(token))
    user = gh.get_user()
    print(f"\n✓ Authenticated as: {user.login}")

    try:
        repo = gh.get_repo(REPO_SLUG)
        print(f"✓ Repo already exists: {repo.html_url}")
    except Exception:
        print(f"\n→ Creating repo {REPO_SLUG} ...")
        repo = user.create_repo(
            REPO_NAME,
            description=DESCRIPTION,
            private=False,
            auto_init=False,
        )
        print(f"✓ Created: {repo.html_url}")

    # Token is passed via git credential helper, not embedded in the URL,
    # to avoid secret-scanning false positives.
    remote_url = f"https://github.com/{REPO_SLUG}.git"

    # ── 2. Write .gitignore and README into the target dir ───────────────────
    (TARGET_DIR / ".gitignore").write_text(GITIGNORE, encoding="utf-8")
    (TARGET_DIR / "README.md").write_text(README, encoding="utf-8")
    print("\n✓ Wrote .gitignore and README.md")

    # ── 3. Init git repo, commit seeded code, push to main ───────────────────
    git_env = {
        "GIT_AUTHOR_NAME":    "SecurityBrain",
        "GIT_AUTHOR_EMAIL":   "securitybrain@aci.local",
        "GIT_COMMITTER_NAME": "SecurityBrain",
        "GIT_COMMITTER_EMAIL":"securitybrain@aci.local",
    }

    git_dir = TARGET_DIR / ".git"
    if git_dir.exists():
        print("\n→ Git repo already initialised — resetting remote and re-pushing ...")
        try:
            run(["git", "remote", "remove", "origin"])
        except Exception:
            pass
    else:
        print("\n→ Initialising git repo ...")
        run(["git", "init", "-b", "main"])

    run(["git", "remote", "add", "origin", remote_url])
    run(["git", "add", "-A"])
    try:
        run(["git", "commit", "-m", "feat: seeded vulnerable payments API (PCI-DSS demo)"], env=git_env)
    except subprocess.CalledProcessError:
        print("   (nothing new to commit — already committed)")

    print("\n→ Pushing to main ...")
    run(["git", "push", "-u", "origin", "main", "--force"])

    print(f"\n{'='*60}")
    print(f"✓ Done! Repo is live:")
    print(f"  {repo.html_url}")
    print(f"\n  Use this in the UI:")
    print(f"  GitHub repo slug : {REPO_SLUG}")
    print(f"  GitHub token     : (set GITHUB_TOKEN env var)")
    print(f"  Base branch      : main")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
