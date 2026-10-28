#!/usr/bin/env python3
"""b-sentinel — the Bayora Sentinel development launcher.

This is a *development* entry point, not the production ``sentinel`` CLI from
SPEC.md. It does not ask for a password, does not sign a real session, and does
not boot a hypervisor. It exists so the SentinelOS practice VM (Terminal,
Browser, Mail, Files, Proxy, the attack/defense consoles and the AI sandbox)
can be demonstrated end to end:

    banner -> authorize the dev session -> choose Red/Blue
           -> start the mock broker -> open the sandbox desktop

The real CLI remains ``sentinel`` and is responsible for PBKDF2 login, team
enrollment, token signing, VM boot and SSH. Nothing here changes that contract.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TextIO

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MOCK_SCRIPT = PROJECT_ROOT / "ui" / "mock_server.py"
DEFAULT_PORT = 8099

# Pinkish-violet palette.
FRAME = (192, 132, 252)
WELCOME = (240, 171, 252)
TAGLINE = (167, 139, 250)
WORDMARK = (
    (250, 232, 255),
    (245, 208, 254),
    (232, 121, 249),
    (216, 180, 254),
    (192, 132, 252),
)

ANSI_RESET = "\x1b[0m"
ANSI_CLEAR = "\x1b[2J\x1b[H"
TERMINAL_TITLE = "\x1b]0;b-sentinel — Bayora Sentinel\x07"

# A compact 5-row block font. Every glyph is six columns wide, which keeps
# SENTINEL on one line at a normal 80-column terminal.
GLYPHS: dict[str, tuple[str, ...]] = {
    "S": ("██████", "██    ", "█████ ", "    ██", "██████"),
    "E": ("██████", "██    ", "█████ ", "██    ", "██████"),
    "N": ("██  ██", "███ ██", "██ ███", "██  ██", "██  ██"),
    "T": ("██████", "  ██  ", "  ██  ", "  ██  ", "  ██  "),
    "I": ("  ██  ", "  ██  ", "  ██  ", "  ██  ", "  ██  "),
    "L": ("██    ", "██    ", "██    ", "██    ", "██████"),
}

WELCOME_LINE = "W E L C O M E   T O   T H E"
TAGLINE_LINE = "BAYORA SENTINEL  ·  development launcher"
TEAMS: tuple[tuple[str, str, str], ...] = (
    ("red", "Red team", "attack the model"),
    ("blue", "Blue team", "build defenses"),
)


class LauncherError(RuntimeError):
    """A safe launcher error; never contains a token."""


# ---------------------------------------------------------------------------
# Welcome banner
# ---------------------------------------------------------------------------


def _enable_windows_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def _color_enabled(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    try:
        if not stream.isatty():
            return False
    except Exception:
        return False
    return _enable_windows_ansi()


def _paint(text: str, rgb: tuple[int, int, int], enabled: bool) -> str:
    if not enabled:
        return text
    red, green, blue = rgb
    return f"\x1b[38;2;{red};{green};{blue}m{text}{ANSI_RESET}"


def wordmark(text: str = "SENTINEL") -> tuple[str, ...]:
    rows = ["" for _ in range(5)]
    for index, char in enumerate(text):
        glyph = GLYPHS.get(char.upper())
        if glyph is None:
            continue
        for row in range(5):
            rows[row] += glyph[row]
            if index != len(text) - 1:
                rows[row] += " "
    return tuple(row.rstrip() for row in rows)


def _framed(content: str, inner_width: int) -> str:
    return "│ " + content.center(inner_width - 2) + " │"


def render_banner(
    *,
    color: bool | None = None,
    width: int | None = None,
    stream: TextIO | None = None,
) -> str:
    """Return the welcome banner as plain text or pinkish-violet ANSI text."""
    out = stream if stream is not None else sys.stdout
    enabled = _color_enabled(out) if color is None else color
    columns = width if width is not None else shutil.get_terminal_size((80, 24)).columns

    art = wordmark("SENTINEL")

    if columns < 46:
        lines = [
            _paint(WELCOME_LINE.center(max(len(WELCOME_LINE), 30)), WELCOME, enabled),
            "",
            _paint("SENTINEL", WORDMARK[2], enabled),
            "",
            _paint(TAGLINE_LINE, TAGLINE, enabled),
        ]
        return "\n".join(lines) + "\n"

    if columns < 64:
        display_art = ("SENTINEL",)
        art_lines = [_paint("SENTINEL", WORDMARK[2], enabled)]
    else:
        display_art = art
        art_lines = [
            _paint(line, WORDMARK[index], enabled)
            for index, line in enumerate(art)
        ]

    # The wordmark is 55 columns wide; the welcome line is deliberately small
    # text above it, so the brand reads as a logo rather than a paragraph.
    minimum = 50 if columns >= 64 else 0
    art_width = max(len(line) for line in display_art)
    inner_width = max(
        len(WELCOME_LINE), len(TAGLINE_LINE), art_width, minimum
    ) + 4

    lines: list[str] = []
    if columns >= 64:
        lines.append(_paint("╭" + "─" * inner_width + "╮", FRAME, enabled))
        lines.append(_paint(_framed("", inner_width), FRAME, enabled))
        lines.append(_paint(_framed(WELCOME_LINE, inner_width), WELCOME, enabled))
        lines.append(_paint(_framed("", inner_width), FRAME, enabled))
        for index, line in enumerate(art):
            lines.append(_paint(_framed(line, inner_width), WORDMARK[index], enabled))
        lines.append(_paint(_framed("", inner_width), FRAME, enabled))
        lines.append(_paint(_framed(TAGLINE_LINE, inner_width), TAGLINE, enabled))
        lines.append(_paint(_framed("", inner_width), FRAME, enabled))
        lines.append(_paint("╰" + "─" * inner_width + "╯", FRAME, enabled))
    else:
        lines.append(_paint(WELCOME_LINE.center(inner_width), WELCOME, enabled))
        lines.append("")
        lines.extend(art_lines)
        lines.append("")
        lines.append(_paint(TAGLINE_LINE, TAGLINE, enabled))

    return "\n".join(lines) + "\n"


def _prepare_terminal(stream: TextIO) -> None:
    """Best-effort UTF-8, title and clear for an interactive terminal."""
    try:
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        if stream.isatty():
            _enable_windows_ansi()
            stream.write(TERMINAL_TITLE + ANSI_CLEAR)
            stream.flush()
    except Exception:
        pass


def print_banner(
    *,
    stream: TextIO | None = None,
    color: bool | None = None,
    width: int | None = None,
) -> None:
    out = stream if stream is not None else sys.stdout
    _prepare_terminal(out)
    out.write(render_banner(color=color, width=width, stream=out))
    out.flush()


# ---------------------------------------------------------------------------
# Prompt flow
# ---------------------------------------------------------------------------


def _read(prompt: str, reader: Callable[[str], str]) -> str | None:
    try:
        return reader(prompt)
    except EOFError:
        return None


def authorize(
    *,
    reader: Callable[[str], str] = input,
    writer: Callable[[str], None] = print,
) -> bool:
    """Ask for a demo authorization. Enter means yes."""
    writer("")
    while True:
        answer = _read("  Authorize this development session? [Y/n] ", reader)
        if answer is None:
            return False
        normalized = answer.strip().lower()
        if normalized in ("", "y", "yes"):
            return True
        if normalized in ("n", "no"):
            return False
        writer("  Please answer y or n.")


def choose_team(
    *,
    reader: Callable[[str], str] = input,
    writer: Callable[[str], None] = print,
) -> str | None:
    """Return 'red' or 'blue', or None when input is closed."""
    writer("")
    writer("  Choose your team")
    writer("")
    for number, (role, label, purpose) in enumerate(TEAMS, start=1):
        writer(f"    [{number}] {label:<10} {purpose}")
    writer("")

    while True:
        answer = _read("  Team ❯ ", reader)
        if answer is None:
            return None
        normalized = answer.strip().lower()
        if normalized in ("1", "r", "red", "red team"):
            return "red"
        if normalized in ("2", "b", "blue", "blue team"):
            return "blue"
        writer("  Choose 1 for Red or 2 for Blue.")


def team_name(role: str) -> str:
    return "Red team" if role == "red" else "Blue team"


# ---------------------------------------------------------------------------
# Mock broker lifecycle
# ---------------------------------------------------------------------------


def _base_url(port: int) -> str:
    return f"http://127.0.0.1:{port}"


def _read_tail(path: Path, limit: int = 2400) -> str:
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return data[-limit:].strip()


def mock_ready(base_url: str, timeout: float = 0.6) -> bool:
    request = urllib.request.Request(
        base_url + "/status",
        headers={"Authorization": "Bearer b-sentinel-healthcheck"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                return False
            payload = json.loads(response.read().decode("utf-8"))
        # Confirm this is the mock (which serves the dashboard config), not the
        # real broker accidentally listening on the chosen development port.
        with urllib.request.urlopen(base_url + "/config.js", timeout=timeout) as response:
            if response.status != 200:
                return False
            config_js = response.read(4096).decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("broker") == "up"
        and "window.SENTINEL" in config_js
    )


def _terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


@dataclass
class MockServer:
    base_url: str
    process: subprocess.Popen | None = None
    log_path: Path | None = None

    @property
    def owned(self) -> bool:
        return self.process is not None

    def stop(self) -> None:
        if self.process is not None:
            _terminate_process(self.process)
            self.process = None
        if self.log_path is not None:
            try:
                self.log_path.unlink(missing_ok=True)
            except OSError:
                pass
            self.log_path = None


def start_mock(
    port: int = DEFAULT_PORT,
    *,
    event_interval: float = 2.0,
    leak_after: float = 10.0,
    timeout: float = 12.0,
) -> MockServer:
    """Reuse a healthy mock on this port, or start and own one."""
    base_url = _base_url(port)
    if mock_ready(base_url):
        return MockServer(base_url=base_url)

    descriptor, log_name = tempfile.mkstemp(prefix="b-sentinel-mock-", suffix=".log")
    os.close(descriptor)
    log_path = Path(log_name)
    log_handle = open(log_path, "ab")

    command = [
        sys.executable,
        "-u",
        str(MOCK_SCRIPT),
        "--port",
        str(port),
        "--event-interval",
        str(event_interval),
        "--leak-after",
        str(leak_after),
    ]
    try:
        process = subprocess.Popen(
            command,
            cwd=str(PROJECT_ROOT),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
        )
    except OSError as exc:
        log_handle.close()
        log_path.unlink(missing_ok=True)
        raise LauncherError(f"Could not start the mock broker: {exc}") from None
    finally:
        try:
            log_handle.close()
        except Exception:
            pass

    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if mock_ready(base_url):
                return MockServer(
                    base_url=base_url, process=process, log_path=log_path
                )
            if process.poll() is not None:
                break
            time.sleep(0.1)
    except BaseException:
        _terminate_process(process)
        log_path.unlink(missing_ok=True)
        raise

    _terminate_process(process)
    tail = _read_tail(log_path)
    log_path.unlink(missing_ok=True)
    detail = f"\n{tail}" if tail else ""
    raise LauncherError(
        f"The mock broker did not become ready on 127.0.0.1:{port}.{detail}"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _open_browser(url: str, opener: Callable[..., Any] = webbrowser.open) -> bool:
    try:
        return bool(opener(url, new=2))
    except TypeError:
        try:
            return bool(opener(url))
        except Exception:
            return False
    except Exception:
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="b-sentinel",
        description=(
            "Bayora Sentinel development launcher. Shows the welcome screen, "
            "takes a demo authorization and team choice, starts the mock broker "
            "and opens the sandbox desktop."
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"mock broker port (default {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="print the desktop URL instead of opening a browser",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colour",
    )
    parser.add_argument(
        "--color",
        action="store_true",
        help="force ANSI colour even when output is not detected as a terminal",
    )
    return parser


def main(
    argv: list[str] | None = None,
    *,
    stream: TextIO | None = None,
    reader: Callable[[str], str] = input,
    opener: Callable[..., Any] = webbrowser.open,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    out = stream if stream is not None else sys.stdout
    write = lambda text="": out.write(str(text) + "\n")  # noqa: E731

    if args.no_color:
        banner_color: bool | None = False
    elif args.color:
        banner_color = True
    else:
        banner_color = None
    print_banner(stream=out, color=banner_color)

    try:
        if not authorize(reader=reader, writer=write):
            write("  Session cancelled.")
            return 0

        role = choose_team(reader=reader, writer=write)
        if role is None:
            write("  No team selected — session cancelled.")
            return 0
    except KeyboardInterrupt:
        write("")
        write("  Cancelled.")
        return 130

    write("")
    write(f"  {team_name(role)} selected.")
    write(f"  Booting the SentinelOS range on 127.0.0.1:{args.port}…")
    try:
        server = start_mock(args.port)
    except KeyboardInterrupt:
        write("")
        write("  Cancelled.")
        return 130
    except LauncherError as exc:
        write("")
        write(f"  {exc}")
        write("  Start it manually with: python ui/mock_server.py")
        return 1

    dashboard_url = f"{server.base_url}/_mock/launch/{role}"
    write("  Broker ready." if server.owned else "  Using the mock broker already running here.")
    write("")
    write(f"  Team       {team_name(role)}")
    write(f"  Desktop    {server.base_url}/desktop")
    write(f"  Console    {server.base_url}/")
    write("")
    if args.no_browser:
        write(f"  Open this URL: {dashboard_url}")
    else:
        if _open_browser(dashboard_url, opener):
            write("  Opened the sandbox desktop in your browser.")
        else:
            write("  Could not open a browser automatically. Open this URL:")
            write(f"  {dashboard_url}")
    write("")
    write("  Press Ctrl+C to stop." if server.owned else "  Press Ctrl+C to close the launcher.")
    write("  The browser route selects your team; the token itself stays out of this terminal.")
    out.flush()

    try:
        while True:
            if server.process is not None and server.process.poll() is not None:
                write("")
                write("  The mock broker stopped unexpectedly.")
                return 1
            time.sleep(0.5)
    except KeyboardInterrupt:
        write("")
        write("  Stopping…")
        return 0
    finally:
        server.stop()


if __name__ == "__main__":
    raise SystemExit(main())
