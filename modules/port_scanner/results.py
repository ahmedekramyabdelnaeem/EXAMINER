"""Rendering and saving of port-scan results."""
from __future__ import annotations

from utils.colors import PORT_STATE_STYLES

from .models import STATE_OPEN, ScanResult

FULL_TABLE_LIMIT = 30  # show every state when at most this many ports were scanned


def render_result(ui, result: ScanResult) -> None:
    """Print a human-readable summary of a scan."""
    host = result.target if result.target == result.ip else f"{result.target} ({result.ip})"
    host_state = {True: "up", False: "down", None: "not determined"}[result.host_up]
    status = "CANCELLED (partial results)" if result.cancelled else "completed"
    ui.panel(
        f"Target:    {host}\n"
        f"Scan:      {result.scan_type.upper()} scan, {result.protocol.upper()} "
        f"({result.ports_requested} ports)\n"
        f"Engine:    {result.engine}\n"
        f"Host:      {host_state}\n"
        f"Duration:  {result.duration_seconds}s\n"
        f"Status:    {status}",
        title="Scan Summary", style="warning" if result.cancelled else "info")

    show_all = result.ports_requested <= FULL_TABLE_LIMIT
    shown = result.ports if show_all else result.open_ports()
    if shown:
        rows = []
        for p in shown:
            rows.append([f"{p.port}/{p.protocol}",
                         (p.state.upper(), PORT_STATE_STYLES.get(p.state, "")),
                         (p.service or "-") if p.state == STATE_OPEN else "-",
                         p.version or "-", p.reason or "-"])
        title = "Ports" if show_all else "Open ports"
        ui.table(title, ["Port", "State", "Service", "Version / Banner", "Reason"], rows)
    elif not result.cancelled:
        ui.warning("No open ports were found. Closed or filtered ports may indicate a "
                   "firewall; absence of open ports is not proof the host is unreachable.")

    counts = result.state_counts()
    ui.print("Totals: " + "  ".join(f"{k}={v}" for k, v in counts.items()), style="muted")
    if result.open_ports() == [] and shown:
        ui.warning("No ports in the 'open' state.")

    if result.os_matches:
        ui.print()
        ui.table("OS fingerprint (estimates, not verified)", ["OS guess", "Accuracy"],
                 [[m["name"], f'{m["accuracy"]}%'] for m in result.os_matches])
    if result.command:
        ui.print(f"\nNmap command: {result.command}", style="muted")
    for note in result.notes:
        ui.warning(note)
    for error in result.errors:
        ui.error(error)
