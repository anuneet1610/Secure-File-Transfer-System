import socket
import os
import random
import hashlib
import uuid
import time
import threading
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress, BarColumn, TextColumn,
    TimeElapsedColumn, TransferSpeedColumn, TaskProgressColumn,
)
from rich.text import Text
from rich.rule import Rule
from rich import box
from rich.live import Live
from rich.console import Group
from rich.align import Align
from collections import deque
from datetime import datetime

console = Console()

SOURCE_FILE = input("Enter the file name to transfer: ").strip()
SESSION_ID  = uuid.uuid4().hex[:8]
LOSS_PROB   = 0.3
CHUNK_SIZE  = 10

with open("public.pem", "rb") as f:
    rsa_public_key = serialization.load_pem_public_key(f.read())

def derive_aes_key_iv(our_priv, peer_pub, session_id: str):
    shared = our_priv.exchange(ec.ECDH(), peer_pub)
    derived = HKDF(
        algorithm=hashes.SHA256(), length=48,
        salt=session_id.encode(), info=b"file-transfer-aes-key-iv",
    ).derive(shared)
    return derived[:32], derived[32:]


def send_int(sock, value, size):
    sock.send(value.to_bytes(size, "big"))


def recv_int(sock, size):
    return int.from_bytes(recv_exact(sock, size), "big")


def recv_exact(sock, size):
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf


def step_row(label: str, value: str, status: str = "pending") -> str:
    icons = {"pending": "[dim]○[/dim]", "active": "[yellow]◎[/yellow]",
             "ok": "[green]✔[/green]", "fail": "[red]✘[/red]"}
    return f"  {icons[status]}  [dim]{label:<30}[/dim]  {value}"


# ─────────────────────────────────────────────────────────────────────────────
# Live dashboard state  (written from the transfer thread, rendered by Live)
# ─────────────────────────────────────────────────────────────────────────────
dashboard_lock  = threading.Lock()
log_lines: deque = deque(maxlen=20)

transfer_state = {
    "attempt":     1,
    "seq_no":      0,
    "total":       0,
    "offset":      0,
    "enc_len":     0,
    "lost":        0,
    "retried":     0,
    "timeouts":    0,
    "status":      "starting",
    "started":     time.time(),
}


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def log_event(msg: str, level: str = "info") -> None:
    palette = {
        "info":  "cyan",
        "ok":    "green",
        "warn":  "yellow",
        "error": "red",
        "key":   "magenta",
    }
    c = palette.get(level, "white")
    line = (
        f"[dim]{_ts()}[/dim]  "
        f"[bold {c}]{level.upper():5}[/bold {c}]  "
        f"[{c}]{msg}[/{c}]"
    )
    with dashboard_lock:
        log_lines.append(line)


def ts_update(**kw):
    with dashboard_lock:
        transfer_state.update(kw)


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard builder
# ─────────────────────────────────────────────────────────────────────────────
def build_transfer_dashboard():
    with dashboard_lock:
        s     = dict(transfer_state)
        lines = list(log_lines)

    # ── header ────────────────────────────────────────────────────────────────
    elapsed = int(time.time() - s["started"])
    m, sc   = divmod(elapsed, 60)
    header = (
        f"[bold white]Secure File Transfer — Client[/bold white]   "
        f"[dim]session:[/dim] [cyan]{SESSION_ID}[/cyan]   "
        f"[dim]loss:[/dim] [yellow]{int(LOSS_PROB*100)}%[/yellow]   "
        f"[dim]file:[/dim] [green]{SOURCE_FILE}[/green]   "
        f"[dim]elapsed:[/dim] [white]{m:02d}:{sc:02d}[/white]"
    )
    header_panel = Panel(
        Align.center(Text.from_markup(header), vertical="middle"),
        style="bold", box=box.HORIZONTALS, padding=(0, 1),
    )

    # ── stats table ───────────────────────────────────────────────────────────
    enc_len = max(s["enc_len"], 1)
    pct     = s["offset"] / enc_len
    bar     = (
        f"[green]{'█' * int(pct * 24)}[/green]"
        f"[dim]{'░' * (24 - int(pct * 24))}[/dim]"
        f" [bold]{int(pct * 100):3d}%[/bold]"
    )

    STATUS_COLOUR = {
        "starting":  "yellow",
        "transfer":  "blue",
        "corrupt":   "yellow",
        "retrying":  "yellow",
        "done":      "green",
        "error":     "red",
        "timeout":   "red",
    }
    sc_val = STATUS_COLOUR.get(s["status"], "white")

    tbl = Table(box=box.SIMPLE_HEAD, show_edge=False, header_style="bold dim", expand=True)
    tbl.add_column("Attempt",   justify="right",  width=8)
    tbl.add_column("Progress",  width=32)
    tbl.add_column("Chunks",    justify="right",  width=12)
    tbl.add_column("Lost",      justify="right",  width=7)
    tbl.add_column("Retried",   justify="right",  width=8)
    tbl.add_column("Timeouts",  justify="right",  width=9)
    tbl.add_column("Status",    width=11)

    tbl.add_row(
        f"[bold]#{s['attempt']}[/bold]",
        bar,
        f"{s['seq_no']}/{s['total']}",
        f"[yellow]{s['lost']}[/yellow]",
        f"[cyan]{s['retried']}[/cyan]",
        f"[red]{s['timeouts']}[/red]",
        f"[{sc_val}]{s['status']}[/{sc_val}]",
    )

    stats_panel = Panel(tbl, title="[bold]Transfer Stats[/bold]", box=box.ROUNDED)

    # ── event log ─────────────────────────────────────────────────────────────
    log_text = Text.from_markup(
        "\n".join(lines) if lines else "[dim]no events yet[/dim]"
    )
    log_panel = Panel(log_text, title="[bold]Event Log[/bold]", box=box.ROUNDED)

    return Group(header_panel, stats_panel, log_panel)


with open(SOURCE_FILE, "rb") as f:
    data = f.read()

digest = hashes.Hash(hashes.SHA256())
digest.update(data)
file_hash   = digest.finalize()
file_size   = len(data)
file_size_h = f"{file_size:,} bytes"

console.print()
console.print(Rule(f"[bold]Secure File Transfer[/bold]  [dim]{SESSION_ID}[/dim]"))
console.print()

# ─────────────────────────────────────────────────────────────────────────────
# Handshake panel  (live — steps light up as they complete)
# ─────────────────────────────────────────────────────────────────────────────
hs_steps = {
    "connect":   ("Connecting to server",              "pending", "—"),
    "ephem_gen": ("Generate ephemeral ECDH keypair",   "pending", "—"),
    "send_pub":  ("Send ephemeral public key",         "pending", "—"),
    "recv_sig":  ("Receive server sig + pub key",      "pending", "—"),
    "verify":    ("Verify RSA signature",              "pending", "—"),
    "derive":    ("Derive AES-256 key via HKDF",       "pending", "—"),
}


def render_handshake():
    lines = [step_row(label, val, st) for label, st, val in hs_steps.values()]
    return Panel(
        "\n".join(lines),
        title=f"[bold]ECDH Handshake[/bold]  [dim]session {SESSION_ID}[/dim]",
        box=box.ROUNDED, padding=(0, 1),
    )


def hs_update(key, status, value=""):
    label = hs_steps[key][0]
    hs_steps[key] = (label, status, value)


with Live(render_handshake(), refresh_per_second=8, transient=True) as live:

    hs_update("connect", "active")
    live.update(render_handshake())
    client = socket.socket()
    client.connect(("127.0.0.1", 9999))
    client.settimeout(2)
    hs_update("connect", "ok", "127.0.0.1:9999")
    live.update(render_handshake())

    client.send(b"\x02")
    client.send(SESSION_ID.encode())
    send_int(client, len(SOURCE_FILE.encode()), 4)
    client.send(SOURCE_FILE.encode())

    hs_update("ephem_gen", "active")
    live.update(render_handshake())
    client_ephem_priv    = ec.generate_private_key(ec.SECP256R1())
    client_ephem_pub_der = client_ephem_priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    hs_update("ephem_gen", "ok", f"{len(client_ephem_pub_der)} B")
    live.update(render_handshake())

    hs_update("send_pub", "active")
    live.update(render_handshake())
    send_int(client, len(client_ephem_pub_der), 4)
    client.send(client_ephem_pub_der)
    hs_update("send_pub", "ok", f"{len(client_ephem_pub_der)} B sent")
    live.update(render_handshake())

    hs_update("recv_sig", "active")
    live.update(render_handshake())
    server_sig_len       = recv_int(client, 4)
    server_sig           = recv_exact(client, server_sig_len)
    server_ephem_pub_len = recv_int(client, 4)
    server_ephem_pub_der = recv_exact(client, server_ephem_pub_len)
    hs_update("recv_sig", "ok", f"sig {server_sig_len} B  pub {server_ephem_pub_len} B")
    live.update(render_handshake())

    hs_update("verify", "active")
    live.update(render_handshake())
    try:
        rsa_public_key.verify(
            server_sig, server_ephem_pub_der,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        hs_update("verify", "ok", "RSA OK - no MITM detected")
        live.update(render_handshake())
    except Exception:
        hs_update("verify", "fail", "SIGNATURE INVALID — aborting")
        live.update(render_handshake())
        console.print("\n[bold red]FATAL: Server signature verification failed — possible MITM![/bold red]")
        client.close()
        raise SystemExit(1)

    server_ephem_pub = serialization.load_der_public_key(server_ephem_pub_der)

    hs_update("derive", "active")
    live.update(render_handshake())
    aes_key, iv = derive_aes_key_iv(client_ephem_priv, server_ephem_pub, SESSION_ID)
    fp = aes_key.hex()[:16] + "…"
    hs_update("derive", "ok", f"fingerprint: {fp}")
    live.update(render_handshake())
    time.sleep(0.3)

console.print(render_handshake())
console.print()

cipher         = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
encrypted_data = cipher.encryptor().update(data)

send_int(client, len(encrypted_data), 8)

total_chunks = (len(encrypted_data) + CHUNK_SIZE - 1) // CHUNK_SIZE
ts_update(total=total_chunks, enc_len=len(encrypted_data), started=time.time())

SIGNAL_OK    = b"\x00"
SIGNAL_RETRY = b"\x01"

attempt     = 0
lost_count  = 0
retry_count = 0
timeout_count = 0

log_event(f"Starting transfer  file=[cyan]{SOURCE_FILE}[/cyan]  chunks={total_chunks}  loss={int(LOSS_PROB*100)}%")

with Live(build_transfer_dashboard(), refresh_per_second=4, screen=False) as live:

    while True:
        attempt += 1
        ts_update(attempt=attempt, status="transfer")

        if attempt > 1:
            log_event(f"Retransmission #{attempt} — server detected corruption, re-encrypting…", "warn")
            cipher         = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            encrypted_data = cipher.encryptor().update(data)
            ts_update(enc_len=len(encrypted_data))

        start_seq = recv_int(client, 4)
        log_event(f"Attempt [bold]#{attempt}[/bold] — starting from seq={start_seq}")

        seq_no = start_seq
        offset = seq_no * CHUNK_SIZE
        ts_update(seq_no=seq_no, offset=offset)

        live.update(build_transfer_dashboard())

        while offset < len(encrypted_data):
            chunk = encrypted_data[offset: offset + CHUNK_SIZE]

            # ── client-side packet loss simulation ───────────────────────────
            if random.random() < LOSS_PROB:
                lost_count += 1
                log_event(
                    f"Packet loss simulated (client)  seq={seq_no}  "
                    f"total_lost={lost_count}",
                    "warn",
                )
                ts_update(lost=lost_count)
                live.update(build_transfer_dashboard())

                # drain any stale ACK the server may have queued
                try:
                    recv_int(client, 4)
                except socket.timeout:
                    timeout_count += 1
                    log_event(
                        f"Timeout waiting for ACK after client-loss  seq={seq_no}", "warn"
                    )
                    ts_update(timeouts=timeout_count)
                    live.update(build_transfer_dashboard())
                except Exception:
                    pass
                continue

            # ── send chunk ───────────────────────────────────────────────────
            send_int(client, seq_no, 4)
            send_int(client, len(chunk), 4)
            client.sendall(chunk)

            # ── wait for ACK ─────────────────────────────────────────────────
            try:
                ack = recv_int(client, 4)
                if ack == seq_no:
                    seq_no += 1
                    offset += len(chunk)
                    ts_update(seq_no=seq_no, offset=offset)
                    live.update(build_transfer_dashboard())
                else:
                    retry_count += 1
                    log_event(
                        f"NACK received  got_ack={ack}  expected={seq_no}  retrying",
                        "warn",
                    )
                    ts_update(retried=retry_count)
                    live.update(build_transfer_dashboard())

            except socket.timeout:
                timeout_count += 1
                retry_count   += 1
                log_event(
                    f"Timeout waiting for ACK  seq={seq_no}  "
                    f"total_timeouts={timeout_count}",
                    "error",
                )
                ts_update(timeouts=timeout_count, retried=retry_count, status="timeout")
                live.update(build_transfer_dashboard())
                ts_update(status="transfer")

            except Exception as exc:
                retry_count += 1
                log_event(f"Recv error: {exc}  seq={seq_no}", "error")
                ts_update(retried=retry_count)
                live.update(build_transfer_dashboard())

        send_int(client, seq_no, 4)
        send_int(client, 0, 4)
        client.send(file_hash)
        log_event("End-of-transfer marker + SHA-256 hash sent", "ok")
        live.update(build_transfer_dashboard())

        # ── wait for server verdict ──────────────────────────────────────────
        try:
            signal = recv_exact(client, 1)
        except socket.timeout:
            timeout_count += 1
            log_event("Timeout waiting for server verdict!", "error")
            ts_update(timeouts=timeout_count, status="timeout")
            live.update(build_transfer_dashboard())
            client.close()
            raise SystemExit(1)

        if signal == SIGNAL_OK:
            log_event("Server accepted transfer — integrity verified ✔", "ok")
            ts_update(status="done", seq_no=total_chunks, offset=len(encrypted_data))
            live.update(build_transfer_dashboard())
            break
        elif signal == SIGNAL_RETRY:
            log_event("Server signalled RETRY — hash mismatch, resending…", "warn")
            ts_update(status="retrying", seq_no=0, offset=0)
            live.update(build_transfer_dashboard())
            send_int(client, len(encrypted_data), 8)
        else:
            log_event(f"Unknown signal {signal!r} — aborting", "error")
            ts_update(status="error")
            live.update(build_transfer_dashboard())
            client.close()
            raise SystemExit(1)

client.close()

# ─────────────────────────────────────────────────────────────────────────────
# Result panel
# ─────────────────────────────────────────────────────────────────────────────
console.print()
result_tbl = Table(box=box.SIMPLE, show_header=False, show_edge=False, padding=(0, 2))
result_tbl.add_column(style="dim",        width=22)
result_tbl.add_column(style="bold white", width=40)
result_tbl.add_row("File",           SOURCE_FILE)
result_tbl.add_row("Size",           file_size_h)
result_tbl.add_row("Session",        SESSION_ID)
result_tbl.add_row("AES key",        fp)
result_tbl.add_row("Attempts",       str(attempt))
result_tbl.add_row("Packets lost",   str(lost_count))
result_tbl.add_row("Retransmits",    str(retry_count))
result_tbl.add_row("Timeouts",       str(timeout_count))
result_tbl.add_row("Integrity",      "[green]✔  SHA-256 verified[/green]")

console.print(Panel(
    result_tbl,
    title="[bold green]  Transfer Complete[/bold green]",
    box=box.ROUNDED, padding=(0, 1),
))
console.print()