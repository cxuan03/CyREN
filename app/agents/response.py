"""
ResponseAgent
=============
Role in the pipeline: the final agent. It acts on the event according to its
risk tier, which is the tiered response at the heart of CyREN:

    high      -> block the source IP (iptables) + email the analyst
    uncertain -> route to the Human Approval queue, take no action yet
    low       -> log only

Output written to state:
    action_taken : "blocked" | "awaiting_approval" | "logged"
    blocked      : bool
    report_path  : path to the generated PDF report (for high-risk events)

`ENABLE_IPTABLES` must stay false on the dev machine (blocks are simulated);
enable it only on the SIEM Server VM where the CYREN_BLOCK chain exists.
"""
import subprocess

from config.settings import settings
from app.agents.state import AgentState
from app.services.report_service import generate_report
from app.services.email_service import send_alert_email, build_alert_email


class ResponseAgent:
    def _rule_exists(self, ip: str) -> bool:
        """Check for an existing DROP rule so repeated blocks don't stack."""
        result = subprocess.run(
            ["iptables", "-C", settings.IPTABLES_CHAIN, "-s", ip, "-j", "DROP"],
            capture_output=True,
        )
        return result.returncode == 0

    def block_ip(self, ip: str) -> bool:
        """Add an iptables DROP rule for the source IP (idempotent)."""
        if not settings.ENABLE_IPTABLES:
            # dev/skeleton mode: pretend the rule was added
            print(f"[ResponseAgent] (simulated) would block {ip}")
            return True
        try:
            if self._rule_exists(ip):
                return True
            subprocess.run(
                ["iptables", "-A", settings.IPTABLES_CHAIN, "-s", ip, "-j", "DROP"],
                check=True, capture_output=True,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            print(f"[ResponseAgent] iptables failed: {exc}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove the DROP rule for an IP (used by the dashboard unblock)."""
        if not settings.ENABLE_IPTABLES:
            print(f"[ResponseAgent] (simulated) would unblock {ip}")
            return True
        try:
            subprocess.run(
                ["iptables", "-D", settings.IPTABLES_CHAIN, "-s", ip, "-j", "DROP"],
                check=True, capture_output=True,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            print(f"[ResponseAgent] iptables unblock failed: {exc}")
            return False

    def _recipients(self) -> str:
        """High-risk alerts go to every active user's own Profile email (so an
        analyst who is offline still gets notified), plus ALERT_EMAIL_TO if set.
        This complements the in-browser pop-up, which only reaches whoever is
        online. Returns a comma-joined To list."""
        tos = []
        try:
            from app.models.db import User
            tos = [u.email.strip() for u in User.query.filter_by(is_active=True).all()
                   if u.email and u.email.strip()]
        except Exception:
            pass
        if settings.ALERT_EMAIL_TO:
            tos.append(settings.ALERT_EMAIL_TO.strip())
        seen, out = set(), []
        for t in tos:
            if t.lower() not in seen:
                seen.add(t.lower()); out.append(t)
        return ", ".join(out) or "soc-team@localhost"

    def _send_email(self, state: AgentState):
        # Build the HTML alert (with the direct "open in CyREN" link) and hand
        # it off. send_alert_email logs the full content when SMTP is unset, so
        # the notification is always visible even before SMTP is configured.
        subject, html = build_alert_email(state)
        sent = send_alert_email(to=self._recipients(), subject=subject, html_body=html)
        state["email_sent"] = sent

    def _automation_level(self) -> str:
        """Manager-controlled AI automation policy (defaults 'standard').
        Falls back to the legacy auto_block_enabled boolean if the level is unset."""
        try:
            from app.models.db import Setting
            lvl = Setting.get("automation_level")
            if lvl in ("advisory", "standard", "full_auto"):
                return lvl
            return "standard" if Setting.get_bool("auto_block_enabled", True) else "advisory"
        except Exception:
            return "standard"

    @staticmethod
    def _should_auto_block(level: str, risk: str) -> bool:
        """Whether this risk tier is auto-contained at the given automation level."""
        if level == "full_auto":
            return risk in ("high", "uncertain")
        if level == "standard":
            return risk == "high"
        return False   # advisory: a human approves every block

    # ------------------------------------------------------------------
    def _whitelisted(self, ip: str) -> bool:
        """True when the analysts have put this source on the whitelist."""
        if not ip:
            return False
        try:
            from app.models.db import Whitelist
            return Whitelist.query.filter_by(ip=ip).first() is not None
        except Exception:                            # noqa: BLE001  (no app context / DB)
            return False

    def run(self, state: AgentState) -> AgentState:
        risk = state.get("risk", "low")
        level = self._automation_level()
        state["automation_level"] = level

        # whitelist: the event is still scored and stored, but no block, no email,
        # no pop-up, no ticket; the analysts said this source is theirs
        if self._whitelisted(state.get("source_ip")):
            state["blocked"] = False
            state["action_taken"] = "whitelisted"
            return state

        if risk in ("high", "uncertain"):
            if self._should_auto_block(level, risk):
                blocked = self.block_ip(state.get("source_ip"))
                state["blocked"] = blocked
                state["action_taken"] = "blocked"
                self._send_email(state)          # email + pop-up both fire
                # generate the report last so it reflects the actions taken
                state["report_path"] = generate_report(state)
            else:
                # not auto-contained at this level: route to Human Approval, but
                # still email/pop-up for high risk so a real threat isn't missed
                # (uncertain awaiting is routine and does not email).
                state["blocked"] = False
                state["action_taken"] = "awaiting_approval"
                if risk == "high":
                    self._send_email(state)

        else:  # low
            state["blocked"] = False
            state["action_taken"] = "logged"

        return state


response_agent = ResponseAgent()
def response_node(state: AgentState) -> AgentState:
    return response_agent.run(state)
