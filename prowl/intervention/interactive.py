"""Interactive REPL for manual intervention during crawl."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from prowl.core.engine import CrawlEngine
    from prowl.intervention.approval import ApprovalManager
    from prowl.intervention.manager import InterventionManager

from prowl.intervention.browser_bridge import BrowserBridge

logger = logging.getLogger(__name__)


class InteractiveSession:
    """CLI-based interactive session for handling interventions."""

    def __init__(
        self,
        engine: CrawlEngine,
        manager: InterventionManager,
        approval_manager: ApprovalManager | None = None,
    ) -> None:
        self._engine = engine
        self._manager = manager
        self._approval = approval_manager

    async def run(self) -> None:
        """Start the interactive REPL loop."""
        print("\n[Prowl Interactive Mode]")
        print("Commands: status, cookies <str>, resolve <id>, pause, resume,")
        print("          approvals, approve <id>, reject <id>, approve-all, quit\n")

        while True:
            try:
                line = await asyncio.to_thread(input, "prowl> ")
                line = line.strip()
                if not line:
                    continue

                parts = line.split(maxsplit=1)
                cmd = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "quit" or cmd == "exit":
                    break
                elif cmd == "status":
                    self._print_status()
                elif cmd == "cookies":
                    self._inject_cookies(arg)
                elif cmd == "curl":
                    self._inject_from_curl(arg)
                elif cmd == "resolve":
                    await self._resolve_intervention(arg)
                elif cmd == "pause":
                    self._engine.pause()
                    print("Engine paused.")
                elif cmd == "resume":
                    self._engine.resume()
                    print("Engine resumed.")
                elif cmd == "interventions":
                    self._list_interventions()
                elif cmd == "approvals":
                    self._list_approvals()
                elif cmd == "approve":
                    await self._approve_request(arg)
                elif cmd == "reject":
                    await self._reject_request(arg)
                elif cmd == "approve-all":
                    await self._approve_all()
                else:
                    print(f"Unknown command: {cmd}")

            except (EOFError, KeyboardInterrupt):
                break
            except Exception as e:
                print(f"Error: {e}")

    def _print_status(self) -> None:
        stats = self._engine.get_stats()
        print(f"  State: {stats['state']}")
        print(f"  Elapsed: {stats['elapsed']:.1f}s")
        print(f"  Requests: {stats['requests_completed']} done, {stats['requests_failed']} failed")
        print(f"  Queue: {stats['queue_size']} pending")
        print(f"  Endpoints: {stats['endpoints_found']}")
        if self._manager.has_pending:
            print(f"  Interventions: {len(self._manager.pending_interventions)} pending")

    def _inject_cookies(self, cookie_string: str) -> None:
        cookies = BrowserBridge.parse_cookie_string(cookie_string)
        if cookies:
            for role_name in self._engine.sessions.role_names:
                self._engine.sessions.update_session_cookies(role_name, cookies)
            print(f"  Injected {len(cookies)} cookies.")
        else:
            print("  Usage: cookies name=value; name2=value2")

    def _inject_from_curl(self, curl_command: str) -> None:
        result = BrowserBridge.parse_curl_command(curl_command)
        cookies = result.get("cookies", {})
        if cookies:
            for role_name in self._engine.sessions.role_names:
                self._engine.sessions.update_session_cookies(role_name, cookies)
            print(f"  Extracted {len(cookies)} cookies from curl command.")
        else:
            print("  No cookies found in curl command.")

    def _list_interventions(self) -> None:
        for i in self._manager.get_all():
            status = "PENDING" if i["state"] == "pending" else i["state"].upper()
            print(f"  [{i['id']}] {status} -- {i['kind']}: {i['message']}")

    async def _resolve_intervention(self, intervention_id: str) -> None:
        if not intervention_id:
            print("  Usage: resolve <intervention_id>")
            return
        success = await self._manager.resolve(intervention_id)
        if success:
            print(f"  Intervention {intervention_id} resolved.")
        else:
            print(f"  Intervention {intervention_id} not found or already resolved.")

    # --- Approval commands ---

    def _list_approvals(self) -> None:
        if not self._approval:
            print("  Approval guardrail not enabled.")
            return
        items = self._approval.get_all()
        pending = [i for i in items if i["state"] == "pending"]
        if not pending:
            print("  No pending approvals.")
            return
        print(f"  {len(pending)} pending approval(s):")
        for i in pending:
            req = i["request"]
            body_hint = f" body={req['body'][:60]}..." if req.get("body") else ""
            print(f"  [{i['id']}] {i['kind']} -- {req['method']} {req['url']}{body_hint}")

    async def _approve_request(self, item_id: str) -> None:
        if not self._approval:
            print("  Approval guardrail not enabled.")
            return
        if not item_id:
            print("  Usage: approve <id>")
            return
        req = await self._approval.approve(item_id)
        if req:
            print(f"  Approved: {req.method.upper()} {req.url}")
        else:
            print(f"  Item {item_id} not found or already resolved.")

    async def _reject_request(self, item_id: str) -> None:
        if not self._approval:
            print("  Approval guardrail not enabled.")
            return
        if not item_id:
            print("  Usage: reject <id>")
            return
        success = await self._approval.reject(item_id)
        if success:
            print(f"  Rejected: {item_id}")
        else:
            print(f"  Item {item_id} not found or already resolved.")

    async def _approve_all(self) -> None:
        if not self._approval:
            print("  Approval guardrail not enabled.")
            return
        approved = await self._approval.approve_all()
        print(f"  Approved {len(approved)} request(s).")
