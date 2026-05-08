import socket
import os
import random
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box
from collections import deque
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# Long-term RSA identity key  (signing only — never for key transport)
# ─────────────────────────────────────────────────────────────────────────────
rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_public_key  = rsa_private_key.public_key()
LOSS_PROB       = 0.3

with open("public.pem", "wb") as f:
    f.write(rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

# ─────────────────────────────────────────────────────────────────────────────
# Shared dashboard state  (all writes take dashboard_lock)
# ─────────────────────────────────────────────────────────────────────────────
dashboard_lock = threading.Lock()
sessions: dict[str, dict] = {}        # session_id → fields
log_lines: deque = deque(maxlen=16)   # scrolling event log


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def log_event(session_id: str, msg: str, level: str = "info") -> None:
    palette = {"info": "cyan", "ok": "green", "warn": "yellow", "error": "red", "key": "magenta"}
    c = palette.get(level, "white")
    line = (
        f"[dim]{_ts()}[/dim]  "
        f"[bold {c}]{level.upper():5}[/bold {c}]  "
        f"[{c}]{session_id}[/{c}]  {msg}"
    )
    with dashboard_lock:
        log_lines.append(line)


def session_update(sid: str, **kw) -> None:
    with dashboard_lock:
        if sid not in sessions:
            sessions[sid] = {
                "addr": "?", "filename": "?", "status": "connecting",
                "chunks_done": 0, "chunks_total": 0,
                "attempts": 0, "fingerprint": "—",
                "started": time.time(),
            }
        sessions[sid].update(kw)


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard builder — called ~4 times/sec by rich.Live
# ─────────────────────────────────────────────────────────────────────────────
RSA_FP = rsa_public_key.public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)[:6].hex(":").upper()


def build_dashboard():
    # ── header ────────────────────────────────────────────────────────────────
    active = threading.active_count() - 1
    header = (
        f"[bold white]Secure File Transfer — Server[/bold white]   "
        f"[dim]RSA:[/dim] [cyan]{RSA_FP}…[/cyan]   "
        f"[dim]loss:[/dim] [yellow]{int(LOSS_PROB*100)}%[/yellow]   "
        f"[dim]port:[/dim] [green]9999[/green]   "
        f"[dim]connections:[/dim] [bold white]{active}[/bold white]"
    )
    header_panel = Panel(
        Align.center(Text.from_markup(header), vertical="middle"),
        style="bold", box=box.HORIZONTALS, padding=(0, 1),
    )

    # ── sessions table ────────────────────────────────────────────────────────
    tbl = Table(
        box=box.SIMPLE_HEAD, show_edge=False,
        header_style="bold dim", expand=True,
    )
    tbl.add_column("Session",   style="cyan",    width=10, no_wrap=True)
    tbl.add_column("Client",    style="white",   width=17, no_wrap=True)
    tbl.add_column("File",      style="white",   width=14, no_wrap=True)
    tbl.add_column("Progress",  width=26)
    tbl.add_column("Chunks",    justify="right", width=10)
    tbl.add_column("Tries",     justify="right", width=5)
    tbl.add_column("ECDH key",  style="magenta", width=20, no_wrap=True)
    tbl.add_column("Status",    width=11)
    tbl.add_column("Elapsed",   justify="right", width=7)

    STATUS_COLOUR = {
        "connecting": "yellow", "handshake": "cyan",
        "transfer": "blue",     "corrupt": "yellow",
        "done": "green",        "error": "red",
    }

    with dashboard_lock:
        snap = dict(sessions)

    for sid, s in snap.items():
        done  = s["chunks_done"]
        total = max(s["chunks_total"], 1)
        pct   = done / total
        bar   = (
            f"[green]{'█' * int(pct * 18)}[/green]"
            f"[dim]{'░' * (18 - int(pct * 18))}[/dim]"
            f" [bold]{int(pct*100):3d}%[/bold]"
        )
        elapsed = int(time.time() - s["started"])
        m, sc  = divmod(elapsed, 60)
        sc_val = STATUS_COLOUR.get(s["status"], "white")
        tbl.add_row(
            sid, s["addr"], s["filename"], bar,
            f"{done}/{s['chunks_total']}",
            str(s["attempts"]),
            s["fingerprint"],
            f"[{sc_val}]{s['status']}[/{sc_val}]",
            f"{m:02d}:{sc:02d}",
        )

    if not snap:
        tbl.add_row("—", "—", "—", "[dim]waiting for connections…[/dim]",
                    "—", "—", "—", "—", "—")

    sessions_panel = Panel(tbl, title="[bold]Active Sessions[/bold]", box=box.ROUNDED)

    # ── log ───────────────────────────────────────────────────────────────────
    with dashboard_lock:
        lines = list(log_lines)
    log_text = Text.from_markup(
        "\n".join(lines) if lines else "[dim]no events yet[/dim]"
    )
    log_panel = Panel(log_text, title="[bold]Event Log[/bold]", box=box.ROUNDED)

    # stack vertically — rich will render top→bottom
    from rich.console import Group
    return Group(header_panel, sessions_panel, log_panel)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
file_locks      = {}
file_locks_lock = threading.Lock()


def get_file_lock(fp):
    with file_locks_lock:
        if fp not in file_locks:
            file_locks[fp] = threading.Lock()
        return file_locks[fp]


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


def derive_aes_key_iv(our_priv, peer_pub, session_id: str):
    shared = our_priv.exchange(ec.ECDH(), peer_pub)
    derived = HKDF(
        algorithm=hashes.SHA256(), length=48,
        salt=session_id.encode(), info=b"file-transfer-aes-key-iv",
    ).derive(shared)
    return derived[:32], derived[32:]


# ─────────────────────────────────────────────────────────────────────────────
# Per-client handler
# ─────────────────────────────────────────────────────────────────────────────
def handle_client(conn, addr):
    SIGNAL_OK    = b"\x00"
    SIGNAL_RETRY = b"\x01"
    addr_str     = f"{addr[0]}:{addr[1]}"

    version = recv_exact(conn, 1)
    if version != b"\x02":
        log_event("?", f"Unsupported version {version!r} from {addr_str}", "error")
        conn.close()
        return

    session_id = recv_exact(conn, 8).decode()
    fname_len  = recv_int(conn, 4)
    filename   = recv_exact(conn, fname_len).decode()

    session_update(session_id, addr=addr_str, filename=filename, status="handshake")
    log_event(session_id, f"New connection from [bold]{addr_str}[/bold]  file=[cyan]{filename}[/cyan]")

    # receive client ephemeral key
    client_ephem_pub_len = recv_int(conn, 4)
    client_ephem_pub_der = recv_exact(conn, client_ephem_pub_len)
    client_ephem_pub     = serialization.load_der_public_key(client_ephem_pub_der)
    log_event(session_id, f"Client ephemeral pub key  ({client_ephem_pub_len} B)", "key")

    # generate server ephemeral keypair
    server_ephem_priv    = ec.generate_private_key(ec.SECP256R1())
    server_ephem_pub_der = server_ephem_priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # sign + send
    server_sig = rsa_private_key.sign(
        server_ephem_pub_der,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    log_event(session_id, "Ephemeral key signed with RSA identity key", "key")

    send_int(conn, len(server_sig), 4);  conn.send(server_sig)
    send_int(conn, len(server_ephem_pub_der), 4);  conn.send(server_ephem_pub_der)

    # ECDH key derivation
    aes_key, iv = derive_aes_key_iv(server_ephem_priv, client_ephem_pub, session_id)
    fp = aes_key.hex()[:16] + "…"
    session_update(session_id, fingerprint=fp, status="transfer")
    log_event(session_id, f"ECDH done  AES-256 fingerprint=[magenta]{fp}[/magenta]", "ok")

    # transfer loop
    file_size    = recv_int(conn, 8)
    CHUNK_SIZE   = 10
    filepath     = f"partial_{session_id}_{filename}"
    file_lock    = get_file_lock(filepath)
    total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    session_update(session_id, chunks_total=total_chunks)
    attempt = 0

    while True:
        attempt += 1
        session_update(session_id, attempts=attempt)
        log_event(session_id, f"Transfer attempt [bold]#{attempt}[/bold]")

        # with file_lock:
        #     if os.path.exists(filepath):
        #         current_size = os.path.getsize(filepath)
        #         start_seq    = current_size // CHUNK_SIZE
        #         with open(filepath, "rb+") as pf:
        #             pf.truncate(start_seq * CHUNK_SIZE)
        #     else:
        #         start_seq = 0

        start_seq = 0

        send_int(conn, start_seq, 4)
        log_event(session_id, "Starting transfer")

        pf = open(filepath, "wb")
        expected_seq = start_seq
        transfer_complete = False

        while True:
            seq_no     = recv_int(conn, 4)
            chunk_size = recv_int(conn, 4)
            if chunk_size == 0:
                transfer_complete = True
                break
            chunk = recv_exact(conn, chunk_size)

            if random.random() < LOSS_PROB:
                log_event(session_id, f"Packet loss simulated  seq={seq_no}", "warn")
                continue

            if seq_no == expected_seq:
                pf.write(chunk)
                send_int(conn, seq_no, 4)
                expected_seq += 1
                session_update(session_id, chunks_done=expected_seq)
            else:
                log_event(session_id, f"Out-of-order  got={seq_no} want={expected_seq}", "warn")
                send_int(conn, expected_seq - 1, 4)

        pf.close()

        if not transfer_complete:
            log_event(session_id, "Incomplete transfer — partial file kept", "warn")
            session_update(session_id, status="error")
            return False

        recv_hash = recv_exact(conn, 32)
        with open(filepath, "rb") as pf:
            encrypted_data = pf.read()

        if random.random() > 0.2:
            log_event(session_id, "Simulating corruption…", "warn")
            session_update(session_id, status="corrupt")
            buf = bytearray(encrypted_data)
            buf[len(buf) // 2] ^= 0xFF
            encrypted_data = bytes(buf)

        cipher         = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        decrypted_data = cipher.decryptor().update(encrypted_data)

        digest = hashes.Hash(hashes.SHA256())
        digest.update(decrypted_data)
        calc_hash = digest.finalize()

        if calc_hash == recv_hash:
            log_event(session_id, f"Integrity [green]OK[/green] — saved after attempt #{attempt}", "ok")
            conn.send(SIGNAL_OK)
            out_path = f"recv_{session_id}_{filename}"
            with open(out_path, "wb") as pf:
                pf.write(decrypted_data)
            with file_lock:
                if os.path.exists(filepath):
                    os.remove(filepath)
            session_update(session_id, status="done", chunks_done=total_chunks)
            log_event(session_id, f"Saved → [cyan]{out_path}[/cyan]", "ok")
            conn.close()
            return True
        else:
            log_event(session_id, f"Hash mismatch attempt #{attempt} — requesting retry", "warn")
            session_update(session_id, status="corrupt")
            conn.send(SIGNAL_RETRY)
            with file_lock:
                if os.path.exists(filepath):
                    os.remove(filepath)
            file_size    = recv_int(conn, 8)
            total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
            session_update(session_id, chunks_total=total_chunks, chunks_done=0, status="transfer")


def client_thread(conn, addr):
    try:
        handle_client(conn, addr)
    except ConnectionResetError:
        log_event(str(addr), "Client disconnected — partial file kept", "warn")
    except Exception as e:
        log_event(str(addr), f"Error: {e}", "error")
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point — live dashboard loop
# ─────────────────────────────────────────────────────────────────────────────
server_sock = socket.socket()
server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_sock.bind(("0.0.0.0", 9999))
server_sock.listen(5)
server_sock.settimeout(0.25)

log_event("server", "RSA keypair ready  public key → [cyan]public.pem[/cyan]", "ok")
log_event("server", "Listening on [green]0.0.0.0:9999[/green]", "info")

with Live(build_dashboard(), refresh_per_second=4, screen=True) as live:
    while True:
        live.update(build_dashboard())
        try:
            conn, addr = server_sock.accept()
            t = threading.Thread(target=client_thread, args=(conn, addr), daemon=True)
            t.start()
        except socket.timeout:
            pass