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
from app.services.email_service import send_alert_email


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

    def _send_email(self, state: AgentState):
        if not settings.ALERT_EMAIL_TO or not settings.SMTP_HOST:
            return
        send_alert_email(
            to=settings.ALERT_EMAIL_TO,
            subject=f"[CyREN] High risk: {state.get('attack_type')} from {state.get('source_ip')}",
            body=str(state.get("llm_summary", {})),
        )

    # ------------------------------------------------------------------
    def run(self, state: AgentState) -> AgentState:
        risk = state.get("risk", "low")

        if risk == "high":
            blocked = self.block_ip(state.get("source_ip"))
            state["blocked"] = blocked
            state["action_taken"] = "blocked"
            self._send_email(state)
            # generate the report last so it reflects the actions taken
            state["report_path"] = generate_report(state)

        elif risk == "uncertain":
            state["blocked"] = False
            state["action_taken"] = "awaiting_approval"

        else:  # low
            state["blocked"] = False
            state["action_taken"] = "logged"

        return state


response_agent = ResponseAgent()
def response_node(state: AgentState) -> AgentState:
    return response_agent.run(state)
