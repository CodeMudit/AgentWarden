#!/usr/bin/env python3
"""
Records the AgentWarden demo as separate 1920x1080 clips with Playwright.

Run on YOUR machine, from the repo root, AFTER:
    PYTHONPATH=. python scripts/seed.py --reset
    uvicorn app.main:app --port 8000          (leave running)

Usage:
    python record.py                 # all scenes
    python record.py --only 02,07    # just some scenes
    python record.py --skip 09       # skip the manual simulator scene
    python record.py --base http://localhost:8000

Output (in ./clips): <scene>.webm, <scene>.events.json (click/focus boxes + timestamps
used for automatic zooms), <scene>.texts.json (page text, used for fact-checking),
and PNG screenshots. Locators are text-based (no access to the templates when this
was written), so if one is missing the scene saves a screenshot, reports it, and
carries on. Send me everything in ./clips.
"""
import argparse
import json
import re
import shutil
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

W, H = 1920, 1080
OUT = Path("clips")
RAW = OUT / "_raw"
STATE = Path(".state")  # logged-in cookies; do NOT commit or share

USERS = {
    "admin": ("admin@demo.local", "demo-admin-pass"),
    "reviewer_a": ("reviewer_a@demo.local", "demo-reviewer-pass"),  # owns refund-bot
    "reviewer_b": ("reviewer_b@demo.local", "demo-reviewer-pass"),  # owns email-assistant
    "auditor": ("auditor@demo.local", "demo-auditor-pass"),
}

# Visible cursor (Playwright videos do not show the real one).
CURSOR_JS = """
(() => {
  const mk = () => {
    if (document.getElementById('aw-cursor')) return;
    const d = document.createElement('div');
    d.id = 'aw-cursor';
    d.style.cssText = 'position:fixed;left:-50px;top:-50px;width:26px;height:26px;margin:-13px 0 0 -13px;' +
      'border-radius:50%;background:rgba(255,255,255,.35);border:2px solid #fff;' +
      'box-shadow:0 0 0 2px rgba(0,0,0,.45);z-index:2147483647;pointer-events:none;' +
      'transition:transform .08s ease';
    (document.body || document.documentElement).appendChild(d);
  };
  addEventListener('mousemove', e => { mk(); const d = document.getElementById('aw-cursor');
    d.style.left = e.clientX + 'px'; d.style.top = e.clientY + 'px'; }, true);
  addEventListener('mousedown', () => { const d = document.getElementById('aw-cursor');
    if (d) d.style.transform = 'scale(.7)'; }, true);
  addEventListener('mouseup', () => { const d = document.getElementById('aw-cursor');
    if (d) d.style.transform = 'scale(1)'; }, true);
})();
"""

problems = []  # collected "could not find X" messages


def rx(p):
    return re.compile(p, re.I)


class Clip:
    def __init__(self, browser, name, role, base):
        self.name, self.base, self.role = name, base, role
        kw = dict(
            viewport={"width": W, "height": H},
            record_video_dir=str(RAW),
            record_video_size={"width": W, "height": H},
        )
        sf = STATE / f"{role}.json"
        if sf.exists():
            kw["storage_state"] = str(sf)
        self.ctx = browser.new_context(**kw)
        self.ctx.add_init_script(CURSOR_JS)
        self.page = self.ctx.new_page()
        self.t0 = time.time()
        self.events, self.texts = [], {}
        self.pos = (W // 2, H // 2)
        self.judge_done = False

    # ---- helpers -------------------------------------------------------
    def t(self):
        return round(time.time() - self.t0, 2)

    def pause(self, s):
        self.page.wait_for_timeout(int(s * 1000))

    def log(self, kind, loc=None, note=""):
        box = None
        try:
            box = loc.bounding_box() if loc is not None else None
        except Exception:
            pass
        self.events.append({"t": self.t(), "kind": kind, "box": box, "note": note})

    def settle(self):
        try:
            self.page.wait_for_load_state("networkidle", timeout=4000)
        except Exception:
            pass

    def styled(self, timeout=10):
        """Wait until the Tailwind CDN has styled the page (sidebar link gets wide)."""
        end = time.time() + timeout
        while time.time() < end:
            try:
                b = self.page.get_by_role("link", name=rx(r"^\s*overview")).first.bounding_box()
                if b and b["width"] > 200:
                    return True
            except Exception:
                pass
            self.pause(0.3)
        problems.append(f"[{self.name}] page looked unstyled (CDN slow?). Trim the start of this clip.")
        return False

    def goto(self, path):
        self.page.goto(self.base + path)
        self.settle()
        self.styled()
        self.page.mouse.move(*self.pos)
        self.judge()
        self.pause(0.8)

    def judge(self):
        """Turn on the header 'Judge' (large type) toggle once per clip, if present."""
        if self.judge_done:
            return
        self.judge_done = True
        try:
            size = lambda: self.page.evaluate(
                "parseFloat(getComputedStyle(document.documentElement).fontSize)"
                "+parseFloat(getComputedStyle(document.body).fontSize)"
            )
            before = size()
            self.click_text("judge", wait=0.6, note="judge mode", quiet=True)
            if size() < before:  # it was already on and we just turned it off
                self.click_text("judge", wait=0.6, note="judge mode (restore)", quiet=True)
            self.events.append({"t": self.t(), "kind": "judge", "note": f"size {before}->{size()}"})
        except Exception:
            pass

    def find(self, pattern):
        r = rx(pattern)
        return (
            self.page.get_by_role("button", name=r)
            .or_(self.page.get_by_role("link", name=r))
            .first
        )

    def click_text(self, pattern, wait=1.2, note="", quiet=False, timeout=6000):
        loc = self.find(pattern)
        try:
            loc.wait_for(state="visible", timeout=timeout)
            loc.scroll_into_view_if_needed()
            b = loc.bounding_box()
            x, y = b["x"] + b["width"] / 2, b["y"] + b["height"] / 2
            self.page.mouse.move(x, y, steps=35)
            self.pause(0.45)
            self.log("click", loc, note or pattern)
            self.page.mouse.click(x, y)
            self.pos = (x, y)
            self.pause(wait)
            self.settle()
            return True
        except Exception:
            if not quiet:
                problems.append(f"[{self.name}] could not click: /{pattern}/")
                self.shot("MISSING_" + re.sub(r"\W+", "_", pattern))
            return False

    def nav(self, pattern):
        return self.click_text(pattern, wait=1.0, note="nav " + pattern)

    def focus(self, pattern, hold=2.0):
        loc = self.page.get_by_text(rx(pattern)).first
        try:
            loc.wait_for(state="visible", timeout=4000)
            loc.scroll_into_view_if_needed()
            b = loc.bounding_box()
            self.page.mouse.move(b["x"] + b["width"] / 2, b["y"] + b["height"] / 2, steps=30)
            self.log("focus", loc, pattern)
            self.pause(hold)
            return True
        except Exception:
            problems.append(f"[{self.name}] could not find text: /{pattern}/")
            return False

    def card(self, heading_pattern):
        """The Demo Lab card whose title matches (all buttons just say 'Run')."""
        h = self.page.get_by_text(rx(heading_pattern)).first
        return h.locator("xpath=ancestor::*[.//button][1]")

    def run_card(self, heading_pattern, wait=2.5, note=""):
        try:
            card = self.card(heading_pattern)
            card.wait_for(state="visible", timeout=8000)
            card.scroll_into_view_if_needed()
            btn = card.get_by_role("button", name=rx(r"^\s*run")).first
            b = btn.bounding_box()
            x, y = b["x"] + b["width"] / 2, b["y"] + b["height"] / 2
            self.page.mouse.move(x, y, steps=35)
            self.pause(0.5)
            self.log("click", btn, note or heading_pattern)
            self.page.mouse.click(x, y)
            self.pos = (x, y)
            self.pause(wait)
            self.settle()
            self.log("focus", card, (note or heading_pattern) + " result")
            txt = card.inner_text()
            self.texts[(note or heading_pattern) + " :card"] = txt
            print("   result:", " | ".join(txt.split())[:220])
            self.pause(2.5)
            return True
        except Exception as e:
            problems.append(f"[{self.name}] could not run card /{heading_pattern}/: {e!r}")
            self.shot("MISSING_card_" + re.sub(r"\W+", "_", heading_pattern))
            return False

    def shot(self, label):
        try:
            self.page.screenshot(path=str(OUT / f"{self.name}_{label}.png"))
            self.texts[label] = self.page.inner_text("body")
        except Exception:
            pass

    def finish(self):
        (OUT / f"{self.name}.events.json").write_text(json.dumps(self.events, indent=1))
        (OUT / f"{self.name}.texts.json").write_text(json.dumps(self.texts, indent=1))
        vid = self.page.video
        self.ctx.close()
        try:
            shutil.move(vid.path(), OUT / f"{self.name}.webm")
        except Exception as e:
            problems.append(f"[{self.name}] video not saved: {e}")
        print(f"  saved {self.name}.webm")


# ---- login (off-record) ------------------------------------------------
def login(browser, role, base):
    email, pw = USERS[role]
    ctx = browser.new_context(viewport={"width": W, "height": H})
    p = ctx.new_page()
    p.goto(base + "/login")
    for pat, sel, val in (
        ("email", "input[type=email],input[name=email],input[name=username]", email),
        ("password", "input[type=password]", pw),
    ):
        try:
            p.get_by_label(rx(pat)).first.fill(val, timeout=2000)
        except Exception:
            p.locator(sel).first.fill(val)
    p.get_by_role("button", name=rx(r"sign in|log in|login")).first.click()
    p.wait_for_url(lambda u: "/login" not in u, timeout=10000)
    STATE.mkdir(exist_ok=True)
    ctx.storage_state(path=str(STATE / f"{role}.json"))
    ctx.close()
    print(f"  logged in as {role} (not recorded)")


# ---- scenes --------------------------------------------------------------
def s01(c):  # Overview
    c.goto("/")
    c.pause(1.5)
    c.focus(r"ledger", 2.5)
    c.focus(r"operational", 2.0)
    c.shot("overview")
    c.pause(1)


def s02(c):  # Leak customer data -> DENIED
    c.goto("/")
    c.nav(r"demo lab")
    c.pause(1)
    c.run_card(r"leak customer data", note="leak customer data")
    c.shot("leak_result")
    c.pause(1)


def s03(c):  # $40 refund -> ALLOWED
    c.goto("/")
    c.nav(r"demo lab")
    c.pause(1)
    c.run_card(r"small refund", note="small refund")
    c.shot("small_result")
    c.pause(1)


def s04(c):  # Large refund -> HELD
    c.goto("/")
    c.nav(r"demo lab")
    c.pause(1)
    c.run_card(r"large refund", note="large refund")
    c.shot("large_demolab")
    c.nav(r"approval")
    c.focus(r"pending|require|held|approval", 2.5)
    c.shot("approvals_pending")
    c.pause(1)


def s05(c):  # Owner (reviewer_a) sees disabled buttons
    c.goto("/")
    c.nav(r"approval")
    c.pause(1.5)
    btns = c.page.get_by_role("button", name=rx(r"^\s*approve"))
    n = btns.count()
    states = [btns.nth(i).is_disabled() for i in range(min(n, 5))]
    c.events.append({"t": c.t(), "kind": "approve_buttons_disabled", "note": json.dumps(states)})
    if n:
        c.page.mouse.move(*(lambda b: (b["x"] + b["width"] / 2, b["y"] + b["height"] / 2))(btns.first.bounding_box()), steps=30)
        c.log("focus", btns.first, "owner: approve button state")
    else:
        problems.append("[05_owner_view] no Approve button found for reviewer_a")
    c.pause(3)
    c.shot("owner_view")
    c.pause(1)


def s06(c):  # Non-owner (reviewer_b) approves with a written reason
    c.goto("/")
    c.nav(r"approval")
    c.pause(1.2)
    try:
        box = c.page.locator("textarea, input[name=reason], input[placeholder*=eason i]").first
        box.wait_for(state="visible", timeout=5000)
        b = box.bounding_box()
        c.page.mouse.move(b["x"] + 40, b["y"] + b["height"] / 2, steps=30)
        c.log("focus", box, "reason box")
        box.click()
        box.type("Reviewed the request and it looks legitimate for this customer", delay=45)
        c.pause(0.8)
    except Exception:
        problems.append("[06_reviewer_b_approves] reason field not found")
        c.shot("MISSING_reason")
    c.click_text(r"^\s*approve", wait=2.5, note="approve")
    c.shot("approved")
    c.pause(1.5)


def s07(c):  # Ledger verify -> PASS
    c.goto("/")
    c.nav(r"ledger")
    c.pause(1.5)
    c.click_text(r"verify", wait=3.0, note="verify")
    c.focus(r"pass|valid|verified", 2.5)
    c.shot("verify_pass")
    c.pause(1)


def s08(c):  # Tamper -> Verify FAIL
    c.goto("/")
    c.nav(r"demo lab")
    c.pause(1)
    c.run_card(r"tamper with the ledger", note="tamper")
    c.nav(r"ledger")
    c.pause(1.2)
    c.click_text(r"verify", wait=3.5, note="verify after tamper")
    c.focus(r"expected|mismatch|broken|fail", 3.5)
    c.shot("verify_fail")
    c.pause(2)


def s10(c):  # Everything-else montage
    c.goto("/")
    c.nav(r"^\s*agents")
    c.pause(2.5)
    c.focus(r"owner", 1.5)
    c.shot("agents")
    c.click_text(r"audit report", wait=2.5, note="audit report", quiet=True)
    c.shot("audit_report")
    c.goto("/")
    c.nav(r"accountab")
    c.pause(2.5)
    c.shot("accountability")
    c.nav(r"policies")
    c.pause(2.5)
    c.shot("policies")
    c.nav(r"demo lab")
    c.pause(2)
    c.shot("demo_lab")


SCENES = {  # id: (name, role, fn)
    "01": ("01_overview", "admin", s01),
    "02": ("02_leak_denied", "admin", s02),
    "03": ("03_small_refund_allowed", "admin", s03),
    "04": ("04_large_refund_held", "admin", s04),
    "05": ("05_owner_view_disabled", "reviewer_a", s05),
    "06": ("06_reviewer_b_approves", "reviewer_b", s06),
    "07": ("07_verify_pass", "admin", s07),
    "08": ("08_tamper_verify_fail", "admin", s08),
    "10": ("10_montage", "admin", s10),
}


def repair(browser, base):
    """Undo the tamper after clip 08 (off-record) so the DB is clean again."""
    ctx = browser.new_context(viewport={"width": W, "height": H}, storage_state=str(STATE / "admin.json"))
    p = ctx.new_page()
    p.goto(base + "/")
    try:
        p.get_by_role("link", name=rx(r"demo lab")).first.click()
        card = p.get_by_text(rx(r"repair demo")).first.locator("xpath=ancestor::*[.//button][1]")
        card.get_by_role("button", name=rx(r"^\s*run")).first.click()
        p.wait_for_timeout(1500)
        print("  repaired ledger (not recorded)")
    except Exception:
        problems.append("Could not click Repair. Run: PYTHONPATH=. python scripts/tamper.py --repair")
    ctx.close()


def s09_manual(pw, base):
    """Simulator: headed window, you drive it, recording runs until you press Enter."""
    br = pw.chromium.launch(headless=False, args=[f"--window-size={W},{H + 120}"])
    c = Clip(br, "09_simulator", "admin", base)
    c.goto("/")
    c.nav(r"demo lab")
    c.focus(r"simulat", 1.0)
    print(
        "\n>> SIMULATOR (manual): in the open window, lower the auto-allow threshold (e.g. 100 -> 50),\n"
        "   run the replay and show the decisions that flip. Move the mouse slowly.\n"
        "   Press ENTER here when finished."
    )
    input()
    c.shot("simulator_end")
    c.finish()
    br.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8000")
    ap.add_argument("--only", default="")
    ap.add_argument("--skip", default="")
    ap.add_argument("--headed", action="store_true")
    a = ap.parse_args()
    only = {x.strip() for x in a.only.split(",") if x.strip()}
    skip = {x.strip() for x in a.skip.split(",") if x.strip()}
    want = lambda k: (not only or k in only) and k not in skip

    OUT.mkdir(exist_ok=True)
    RAW.mkdir(exist_ok=True)
    with sync_playwright() as pw:
        br = pw.chromium.launch(headless=not a.headed)
        for role in USERS:
            if role == "auditor":
                continue
            login(br, role, a.base)
        for k in sorted(SCENES):
            if not want(k):
                continue
            name, role, fn = SCENES[k]
            print(f"scene {name} ({role})")
            c = Clip(br, name, role, a.base)
            try:
                fn(c)
            except Exception as e:
                problems.append(f"[{name}] crashed: {e!r}")
                c.shot("CRASH")
            c.finish()
            if k == "08":
                repair(br, a.base)
        br.close()
        if want("09"):
            s09_manual(pw, a.base)

    print("\n=== DONE ===")
    if problems:
        print("Problems (send these to me along with ./clips):")
        for p in problems:
            print("  -", p)
    else:
        print("No problems reported. Send me ./clips")
    return 0


if __name__ == "__main__":
    sys.exit(main())
