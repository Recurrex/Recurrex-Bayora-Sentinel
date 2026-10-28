Bayora Sentinel — style guide
=============================

One reference: the desktop chrome of XFCE / Windows 11. Do not invent a new
style; match its spacing and metrics. Everything below is enforced by
[tokens.css](../ui/web/tokens.css).

Colour
------
* Structure is neutral grey. Windows are `--panel`, chrome is `--panel-2`,
  wells are `--panel-3`, hairlines are `--line` (1px, always).
* Colour is state, not decoration:
  - `--red-team` — red seat sources only. `--blue-team` — blue seat only.
  - `--bad` — the single danger colour. `--warn` — warnings.
  - `--good` — healthy state.
* No purple. No gradients. Colour appears in status and verdicts; icons are
  otherwise monochrome (single 1.5px stroke).

Type
----
* One UI face: `--sans` (Inter or system-ui). One log face: `--mono`
  (JetBrains Mono). No other family.
* Sizes on the `--fs-*` scale. Logs and table numerics use
  `font-variant-numeric: tabular-nums; font-family: var(--mono)`.

Chrome metrics
--------------
* Taskbar height: `--panel-h` 44px. Window title bar: `--titlebar-h` 32px.
* Radii: `--r-sm` 2px, `--r` 3px, `--r-lg` 4px. Nothing more.
* Borders: 1px `--line`; focused elements get `--line-strong`.
* Depth: shadows on the focused window and popovers only
  (`--shadow-win`, `--shadow-pop`). Inactive windows are dimmed, not shadowed.

Layout
------
* One taskbar at the bottom: app pins on the left, one button per open window
  (open/focused states), system tray + clock on the right.
* The desktop itself holds at most four shortcuts: Terminal, Files, Browser,
  Toolbox.
* Status lives in the tray: 16px monochrome icons with tooltips, click for a
  detail popover. No SaaS pill chips.

Windows
-------
* Real windows: drag by title bar, resize from all edges and corners,
  minimize/maximize/close, z-order on focus, edge snapping with a preview,
  geometry persisted in localStorage (`sentinel.wm`). Never persist the token.

Markup rules
------------
* Text from the broker enters the DOM via `textContent`/`createTextNode`
  only — innerHTML is never parsed.
* Tables: `table-layout: fixed`, `white-space: nowrap`, fixed column widths
  from `--col-*`; long logs render through the virtualized list
  (`--row-h` rows).

Copy
----
* Terse and technical. No marketing voice ("Watch for attacks in flight" is
  out). Labels name devices, states and commands: "audit ok", "chain BROKEN",
  "10.66.13.13:3128".
