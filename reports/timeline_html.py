"""
reports/timeline_html.py
Gulf DataStream Labs — Sombra
Self-contained HTML timeline report — Sombra native format.

Features:
  - Summary stats bar (total, flagged, sources, date range)
  - Source category filter buttons
  - Flagged-only toggle
  - Keyword search
  - Flagged events highlighted in red
  - No external dependencies — works offline in any browser
"""

from datetime import datetime
from pathlib import Path
from typing import List, Dict


def generate_html(
    events:    List[Dict],
    case_name: str,
    hostname:  str,
    profile_name: str,
) -> str:
    """
    Build the complete self-contained HTML timeline document.

    Args:
        events:       Sorted list of normalized event dicts.
        case_name:    Case name for the report header.
        hostname:     Target hostname for the report header.
        profile_name: Profile used for this collection.

    Returns:
        Complete HTML document as a string.
    """
    flagged_count = sum(1 for e in events if e.get("flagged"))
    sources       = sorted(set(e["source"] for e in events if e["source"]))
    earliest      = events[0]["ts"][:10]  if events else "—"
    latest        = events[-1]["ts"][:10] if events else "—"

    # Source filter buttons
    src_btns = "".join(
        f'<button class="src-btn" onclick="filterSrc(\'{s}\')">{s}</button> '
        for s in sources
    )

    # Table rows
    rows = []
    for e in events:
        flag_class = ' class="flagged"' if e.get("flagged") else ""
        flag_marker = '<span class="flag">[!]</span> ' if e.get("flagged") else ""
        rows.append(
            f'<tr{flag_class} data-source="{e["source"]}" '
            f'data-desc="{e["description"].lower()}">'
            f'<td>{e["ts"]}</td>'
            f'<td>{e["source"]}</td>'
            f'<td>{e["eid"]}</td>'
            f'<td>{flag_marker}{e["description"]}</td>'
            f'<td>{e["artifact"]}</td>'
            f'</tr>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sombra Timeline — {case_name} — {hostname}</title>
<style>
  body     {{ font-family: Arial, sans-serif; font-size: 12px; margin: 20px; color: #111; }}
  h1       {{ font-size: 15px; margin: 0 0 4px 0; }}
  .brand   {{ font-size: 10px; color: #888; margin-bottom: 12px; }}
  .meta    {{ font-size: 11px; color: #555; margin-bottom: 10px; }}
  .stats   {{ display: inline-flex; gap: 10px; margin-bottom: 12px; }}
  .stat    {{ background: #f4f4f4; border: 1px solid #ddd; border-radius: 4px;
              padding: 6px 14px; font-size: 11px; text-align: center; }}
  .stat b  {{ display: block; font-size: 18px; color: #222; }}
  .stat.fl b {{ color: #c00; }}
  .filters {{ margin-bottom: 8px; font-size: 11px; }}
  .search  {{ margin-bottom: 8px; font-size: 11px; }}
  .search input {{ font-size: 11px; padding: 3px 8px; border: 1px solid #bbb;
                   border-radius: 3px; width: 250px; }}
  button   {{ font-size: 11px; padding: 3px 10px; border: 1px solid #bbb;
              background: #fff; border-radius: 3px; cursor: pointer; margin-right: 4px; }}
  button:hover   {{ background: #eee; }}
  button.active  {{ background: #333; color: #fff; border-color: #333; }}
  button.flg-btn {{ border-color: #c00; color: #c00; }}
  button.flg-btn.active {{ background: #c00; color: #fff; }}
  #cnt     {{ font-size: 11px; color: #555; margin-bottom: 6px; }}
  table    {{ border-collapse: collapse; width: 100%; font-size: 11px; }}
  th       {{ background: #eee; border: 1px solid #ccc; padding: 5px 8px; text-align: left; white-space: nowrap; }}
  td       {{ border: 1px solid #ddd; padding: 4px 8px; vertical-align: top; font-family: monospace; }}
  tr.flagged td {{ background: #fff5f5; }}
  tr.hidden     {{ display: none; }}
  .flag    {{ color: #c00; font-weight: bold; }}
</style>
</head>
<body>
<h1>Sombra Timeline Report</h1>
<div class="brand">Gulf DataStream Labs — Profile: {profile_name}</div>
<div class="meta">
  Case: <b>{case_name}</b> &nbsp;|&nbsp;
  Host: <b>{hostname}</b> &nbsp;|&nbsp;
  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</div>
<div class="stats">
  <div class="stat"><b>{len(events):,}</b>Total Events</div>
  <div class="stat fl"><b>{flagged_count:,}</b>Flagged</div>
  <div class="stat"><b>{len(sources)}</b>Sources</div>
  <div class="stat"><b>{earliest}</b>Earliest</div>
  <div class="stat"><b>{latest}</b>Latest</div>
</div>
<div class="filters">
  <span>Filter: </span>
  <button id="btn-all" class="active" onclick="filterSrc('all')">All</button>
  <button class="flg-btn" onclick="toggleFlagged()">&#9873; Flagged Only</button>
  {src_btns}
</div>
<div class="search">
  <input type="text" id="searchbox" placeholder="Search descriptions..." oninput="doSearch()">
</div>
<div id="cnt"></div>
<table>
  <thead><tr>
    <th>Timestamp</th>
    <th>Source</th>
    <th>Event ID</th>
    <th>Description</th>
    <th>Artifact File</th>
  </tr></thead>
  <tbody id="tb">{"".join(rows)}</tbody>
</table>
<script>
var curSrc = 'all';
var flagOnly = false;
var searchTerm = '';

function update() {{
  var rows = document.querySelectorAll('#tb tr');
  var visible = 0;
  rows.forEach(function(r) {{
    var srcOk  = curSrc === 'all' || r.dataset.source === curSrc;
    var flgOk  = !flagOnly || r.classList.contains('flagged');
    var schOk  = !searchTerm || (r.dataset.desc || '').includes(searchTerm);
    var show   = srcOk && flgOk && schOk;
    r.classList.toggle('hidden', !show);
    if (show) visible++;
  }});
  document.getElementById('cnt').textContent = visible.toLocaleString() + ' events shown';
}}

function filterSrc(s) {{
  curSrc = s; flagOnly = false;
  document.querySelectorAll('button').forEach(function(b) {{ b.classList.remove('active'); }});
  document.getElementById('btn-all').classList.add('active');
  update();
}}

function toggleFlagged() {{
  flagOnly = !flagOnly; curSrc = 'all';
  document.querySelectorAll('button').forEach(function(b) {{ b.classList.remove('active'); }});
  document.querySelector('.flg-btn').classList.toggle('active', flagOnly);
  document.getElementById('btn-all').classList.toggle('active', !flagOnly);
  update();
}}

function doSearch() {{
  searchTerm = document.getElementById('searchbox').value.toLowerCase();
  update();
}}

update();
</script>
</body>
</html>"""


def write_html_timeline(
    case_dir:     Path,
    case_name:    str,
    hostname:     str,
    profile_name: str,
    events:       List[Dict],
    log,
) -> Path:
    """
    Write the HTML timeline report to the case folder.

    Args:
        case_dir:     Path to the case output folder.
        case_name:    Case name string.
        hostname:     Target hostname.
        profile_name: Profile name for the report header.
        events:       Parsed and sorted event list.
        log:          Callable for status logging.

    Returns:
        Path to the written HTML file.
    """
    html = generate_html(events, case_name, hostname, profile_name)
    out  = case_dir / "Sombra_Timeline.html"
    out.write_text(html, encoding="utf-8")
    flagged = sum(1 for e in events if e.get("flagged"))
    log(f"  -> Saved: Sombra_Timeline.html ({len(events):,} events, {flagged} flagged)")
    return out
