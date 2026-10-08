"""
 Network Packet Analyzer
------------------------------------------------
Tkinter + Scapy packet sniffer with:
 
  * PACKET FEED tab  : live table, protocol layers, hex dump, payload)
  * NETWORK MAP tab  : interactive graph 
  * Live stats       : protocol chart, packets/sec, bytes, top talkers
  * Threat alerts    :  many SYNs to many ports from one host
  * Features :  filter, save / open .pcap files

Installation guide 
  pip install scapy         
  Windows : install Npcap (https://npcap.com) and run as Administrator
  Linux / macOS : sudo python3 PACKET CAPTURE .py

**** === Only capture traffic on networks you own or have permission to monitor === ****

///// For Any Queries Contact Owner: OM_HERE_09
"""

import ipaddress
import math
import queue
import random
import time
import tkinter as tk
from collections import Counter, defaultdict
from tkinter import filedialog, messagebox, ttk

try:
    from scapy.all import (
        ARP, DNS, ICMP, IP, TCP, UDP, AsyncSniffer, Ether, IPv6, Raw,
        get_if_list, rdpcap, wrpcap,
    )
    try:
        from scapy.layers.dns import DNSQR
    except Exception:  
        DNSQR = None
except ImportError:
    raise SystemExit("Scapy is not installed. Run:  pip install scapy")


#  Background colors and fonts

BG = "#070b14"       
PANEL = "#0c1322"    
PANEL2 = "#121c33"    #  elements
GRID = "#1b2a4a"      # borders
CYAN = "#00f0ff"
MAGENTA = "#ff2bd6"
LIME = "#39ff14"
YELLOW = "#fcee0a"
ORANGE = "#ffa63d"
RED = "#ff3860"
FG = "#c8f7ff"
DIM = "#6b7f9e"
PLOT_BG = "#03060d"

FONT = ("Consolas", 10)
FONT_B = ("Consolas", 10, "bold")

PROTO_COLORS = {
    "TCP": "#4dd0ff", "UDP": "#b388ff", "ICMP": MAGENTA, "ARP": YELLOW,
    "DNS": LIME, "HTTP": ORANGE, "TLS": "#00ffc8", "IPv6": "#c792ea",
    "OTHER": "#8899aa",
}
WELL_KNOWN = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 3306: "MySQL", 3389: "RDP",
    5353: "mDNS", 8080: "HTTP-Alt",
}

MAX_PACKETS = 50000     
MAX_NODES = 60           
SCAN_THRESHOLD = 20      #  SYN ports from one source before alerting
POLL_MS = 100
STATS_MS = 1000

# network-map physics / look
LABEL_TOP = 12           # always label this many busiest hosts
LINK_LEN = 85            # preferred edge length (px)
SPRING = 0.045           # edge stiffness
REPULSION = 5200.0       # node-node repulsion strength
REPEL_RANGE2 = 380 ** 2  # ignore repulsion beyond this distance^2
GRAVITY = 0.018          # pulls every node to the centre (keeps islands together)
DAMPING = 0.80
MAX_SPEED = 22.0
COOLING = 0.990          # layout "settles" smoothly; dragging / new hosts re-heat it
ALPHA_MIN = 0.02


# --------------------------------------------------------------------------- #
#  Packet parsing helpers
# --------------------------------------------------------------------------- #
def parse_packet(pkt):
    """Return a dict with the summary fields shown in the table."""
    info = {"src": "-", "dst": "-", "proto": "OTHER", "info": "", "sport": None,
            "dport": None, "ip": False}

    if pkt.haslayer(ARP):
        a = pkt[ARP]
        info.update(src=a.psrc, dst=a.pdst, proto="ARP")
        info["info"] = (f"Who has {a.pdst}? Tell {a.psrc}" if a.op == 1
                        else f"{a.psrc} is at {a.hwsrc}")
        return info

    if pkt.haslayer(IP):
        info["src"], info["dst"], info["ip"] = pkt[IP].src, pkt[IP].dst, True
    elif pkt.haslayer(IPv6):
        info["src"], info["dst"], info["ip"] = pkt[IPv6].src, pkt[IPv6].dst, True
        info["proto"] = "IPv6"
    elif pkt.haslayer(Ether):
        info["src"], info["dst"] = pkt[Ether].src, pkt[Ether].dst

    if pkt.haslayer(TCP):
        t = pkt[TCP]
        info.update(proto="TCP", sport=t.sport, dport=t.dport)
        svc = WELL_KNOWN.get(t.dport) or WELL_KNOWN.get(t.sport)
        info["info"] = f"{t.sport} -> {t.dport} [{t.flags}] Seq={t.seq} Ack={t.ack} Win={t.window}"
        if svc:
            info["info"] = f"({svc}) " + info["info"]
        if svc in ("HTTP", "HTTP-Alt") and pkt.haslayer(Raw):
            first = bytes(pkt[Raw].load).split(b"\r\n", 1)[0][:80]
            if first.startswith((b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"HTTP/")):
                info["proto"] = "HTTP"
                info["info"] = first.decode("latin-1", "replace")
        elif svc == "HTTPS":
            info["proto"] = "TLS"
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        info.update(proto="UDP", sport=u.sport, dport=u.dport)
        info["info"] = f"{u.sport} -> {u.dport} Len={u.len}"
    elif pkt.haslayer(ICMP):
        ic = pkt[ICMP]
        kinds = {0: "Echo reply", 3: "Dest unreachable", 8: "Echo request", 11: "Time exceeded"}
        info.update(proto="ICMP", info=kinds.get(ic.type, f"Type {ic.type}") + f" (code {ic.code})")

    if pkt.haslayer(DNS):
        info["proto"] = "DNS"
        d = pkt[DNS]
        qname = ""
        if DNSQR is not None and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode(errors="replace")
            except Exception:
                qname = str(pkt[DNSQR].qname)
        info["info"] = ("Response " if d.qr else "Query ") + qname
    return info


def layer_tree(pkt):
    """Yield (layer_name, [(field, value_str), ...]) for each layer."""
    layer = pkt
    while layer is not None and layer.__class__.__name__ != "NoPayload":
        rows = []
        for f in layer.fields_desc:
            try:
                val = layer.getfieldval(f.name)
                rows.append((f.name, str(f.i2repr(layer, val))))
            except Exception:
                pass
        yield layer.name, rows
        layer = layer.payload


def hex_dump(data: bytes) -> str:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk).ljust(16 * 3 - 1)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:04x}  {hx}  {asc}")
    return "\n".join(lines)


def payload_text(pkt) -> str:
    if not pkt.haslayer(Raw):
        return "(no application payload)"
    raw = bytes(pkt[Raw].load)
    text = raw.decode("utf-8", errors="replace")
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    if text and printable / len(text) > 0.85:
        return text
    return f"(binary data, {len(raw)} bytes - see hex dump)"


def is_private(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False



#  Interactive network map 

def mix(c1: str, c2: str, t: float) -> str:
    """Blend hex colour c1 toward c2 by t (0..1)."""
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(x + (y - x) * t) for x, y in zip(a, b))


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def short_ip(ip: str) -> str:
    return ip if len(ip) <= 18 else ip[:8] + "…" + ip[-7:]


class NetworkMap(tk.Canvas):
    

    FRAME_MS = 33   # ~30 fps

    def __init__(self, master, on_select=None):
        super().__init__(master, bg=PLOT_BG, highlightthickness=0)
        self.on_select = on_select
        self.nodes, self.edges = {}, {}
        self.adj = defaultdict(set)
        self.alpha = 1.0
        self.frozen = False
        self.auto_fit = True
        self.hover = self.selected = None
        self.scale = self.t_scale = 1.0
        self.ox = self.oy = self.t_ox = self.t_oy = 0.0
        self._drag = self._pan = self._press_node = None
        self._grab = (0.0, 0.0)
        self._press_xy = self._mouse = (0, 0)
        self._moved = False
        self._dirty = self._style_dirty = True
        self._n = 0

        # overlay items (always drawn on top)
        self.title_id = self.create_text(0, 0, text="", fill=CYAN, tags="hud",
                                         font=("Consolas", 12, "bold"))
        self.empty_id = self.create_text(0, 0, text="AWAITING TRAFFIC...", fill=DIM,
                                         tags="hud", font=("Consolas", 14))
        self.leg1 = self.create_text(0, 0, text="● private/LAN", fill=CYAN, anchor="w",
                                     tags="hud", font=("Consolas", 9))
        self.leg2 = self.create_text(0, 0, text="● public/internet", fill=MAGENTA, anchor="w",
                                     tags="hud", font=("Consolas", 9))
        self.leg3 = self.create_text(0, 0, text="◎ pinned", fill=YELLOW, anchor="w",
                                     tags="hud", font=("Consolas", 9))
        self.hint = self.create_text(0, 0, anchor="e", fill=DIM, tags="hud", font=("Consolas", 9),
                                     text="wheel: zoom   drag: pan/move   dbl-click: pin   click: select")
        self.tip_bg = self.create_rectangle(0, 0, 0, 0, fill=PANEL2, outline=CYAN,
                                            state="hidden", tags="tip")
        self.tip_tx = self.create_text(0, 0, anchor="nw", fill=FG, state="hidden",
                                       tags="tip", font=("Consolas", 9))

        self.bind("<Configure>", self._on_resize)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<B1-Motion>", self._on_drag)
        self.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<Double-Button-1>", self._on_double)
        self.bind("<Motion>", self._on_motion)
        self.bind("<Leave>", self._on_leave)
        self.bind("<MouseWheel>", self._on_wheel)       
        self.bind("<Button-4>", self._on_wheel)         
        self.bind("<Button-5>", self._on_wheel)         
        self.after(self.FRAME_MS, self._tick)

    # Public Api
    def add_packet(self, src, dst, length):
        ends = {src, dst}
        new = [ip for ip in ends if ip not in self.nodes]
        if len(self.nodes) + len(new) > MAX_NODES:
            return
        for ip in new:
            self._make_node(ip, dst if ip == src else src)
        for ip in ends:
            nd = self.nodes[ip]
            nd["bytes"] += length
            nd["pkts"] += 1
        if src != dst:
            key = (src, dst) if src < dst else (dst, src)
            e = self.edges.get(key)
            if e:
                e["w"] += 1
            else:
                self._make_edge(key)
        self._dirty = True

    def reset(self):
        self.delete("node", "edge")
        self.nodes.clear()
        self.edges.clear()
        self.adj.clear()
        self.hover = self.selected = None
        self.alpha, self.frozen, self.auto_fit = 1.0, False, True
        self._center_view()
        self.itemconfig("tip", state="hidden")
        self._dirty = self._style_dirty = True
        if self.on_select:
            self.on_select(None)

    def fit(self):
        self.auto_fit = True
        self._fit_targets()

    def relayout(self):
        n = max(len(self.nodes), 1)
        for i, nd in enumerate(self.nodes.values()):
            ang = 2 * math.pi * i / n
            rad = 110 + random.uniform(0, 60)
            nd.update(x=rad * math.cos(ang), y=rad * math.sin(ang), vx=0.0, vy=0.0, pinned=False)
        self.alpha, self.frozen = 1.0, False
        self.fit()
        self._style_dirty = True

    def unpin_all(self):
        for nd in self.nodes.values():
            nd["pinned"] = False
        self.alpha = max(self.alpha, 0.6)
        self._style_dirty = True

    def toggle_freeze(self):
        self.frozen = not self.frozen
        if not self.frozen:
            self.alpha = max(self.alpha, 0.3)
        self._dirty = True
        return self.frozen

    def node_info(self, ip):
        nd = self.nodes.get(ip)
        if not nd:
            return None
        return {"kind": "LAN" if nd["private"] else "INTERNET", "pkts": nd["pkts"],
                "bytes": nd["bytes"], "links": len(self.adj[ip]), "pinned": nd["pinned"]}

    #  graph 
    def _make_node(self, ip, anchor):
        a = self.nodes.get(anchor)
        if a:      
            x, y = a["x"] + random.uniform(-35, 35), a["y"] + random.uniform(-35, 35)
        else:
            x, y = random.gauss(0, 60), random.gauss(0, 60)
        private = is_private(ip)
        col = CYAN if private else MAGENTA
        g2 = self.create_oval(0, 0, 0, 0, fill=mix(col, PLOT_BG, 0.90), outline="", tags="node")
        g1 = self.create_oval(0, 0, 0, 0, fill=mix(col, PLOT_BG, 0.78), outline="", tags="node")
        body = self.create_oval(0, 0, 0, 0, fill=col, outline="#ffffff", width=1, tags="node")
        lab = self.create_text(0, 0, text=short_ip(ip), fill="#e8fbff", anchor="n",
                               font=("Consolas", 8), state="hidden", tags="node")
        self.nodes[ip] = dict(x=x, y=y, vx=0.0, vy=0.0, bytes=0, pkts=0, r=8.0, pinned=False,
                              private=private, col=col, g2=g2, g1=g1, body=body, lab=lab)
        self.tag_raise("hud")
        self.tag_raise("tip")
        self.alpha = max(self.alpha, 0.7)
        self._style_dirty = True

    def _make_edge(self, key):
        line = self.create_line(0, 0, 0, 0, fill=mix(LIME, PLOT_BG, 0.6), width=1, tags="edge")
        self.tag_lower("edge")
        self.edges[key] = {"w": 1, "item": line}
        self.adj[key[0]].add(key[1])
        self.adj[key[1]].add(key[0])
        self.alpha = max(self.alpha, 0.5)
        self._style_dirty = True

    
    def _to_screen(self, x, y):
        return x * self.scale + self.ox, y * self.scale + self.oy

    def _to_world(self, sx, sy):
        return (sx - self.ox) / self.scale, (sy - self.oy) / self.scale

    def _center_view(self):
        w, h = self.winfo_width(), self.winfo_height()
        self.scale = self.t_scale = 1.0
        self.ox = self.t_ox = w / 2
        self.oy = self.t_oy = h / 2

    def _fit_targets(self):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 60 or h < 60 or not self.nodes:
            return
        xs = [n["x"] for n in self.nodes.values()]
        ys = [n["y"] for n in self.nodes.values()]
        minx, maxx, miny, maxy = min(xs) - 30, max(xs) + 30, min(ys) - 30, max(ys) + 40
        bw, bh = max(maxx - minx, 140), max(maxy - miny, 140)
        s = max(0.25, min((w - 100) / bw, (h - 110) / bh, 1.7))
        self.t_scale = s
        self.t_ox = w / 2 - (minx + maxx) / 2 * s
        self.t_oy = h / 2 + 12 - (miny + maxy) / 2 * s

    def _node_at(self, sx, sy):
        best, best_d = None, 1e9
        for ip, n in self.nodes.items():
            px, py = self._to_screen(n["x"], n["y"])
            d = math.hypot(px - sx, py - sy)
            if d <= max(5, n["r"] * self.scale) + 4 and d < best_d:
                best, best_d = ip, d
        return best

    
    def _on_resize(self, e):
        w, h = e.width, e.height
        self.coords(self.title_id, w / 2, 16)
        self.coords(self.empty_id, w / 2, h / 2)
        self.coords(self.leg1, 12, h - 14)
        self.coords(self.leg2, 120, h - 14)
        self.coords(self.leg3, 280, h - 14)
        self.coords(self.hint, w - 12, h - 14)
        if self.auto_fit and self.nodes:
            self._fit_targets()
        elif not self.nodes:
            self._center_view()
        self._dirty = True

    def _on_press(self, e):
        self._press_xy, self._moved = (e.x, e.y), False
        self._press_node = ip = self._node_at(e.x, e.y)
        if ip:
            n = self.nodes[ip]
            wx, wy = self._to_world(e.x, e.y)
            self._grab = (n["x"] - wx, n["y"] - wy)
            self._drag = ip
        else:
            self._pan = (e.x, e.y)

    def _on_drag(self, e):
        if not self._moved:
            if math.hypot(e.x - self._press_xy[0], e.y - self._press_xy[1]) < 4:
                return
            self._moved = True
        if self._drag in self.nodes:
            n = self.nodes[self._drag]
            wx, wy = self._to_world(e.x, e.y)
            n["x"], n["y"] = wx + self._grab[0], wy + self._grab[1]
            n["vx"] = n["vy"] = 0.0
            n["pinned"] = True
            self.alpha = max(self.alpha, 0.35)       
            self._style_dirty = True
        elif self._pan:
            dx, dy = e.x - self._pan[0], e.y - self._pan[1]
            self.ox += dx; self.t_ox += dx
            self.oy += dy; self.t_oy += dy
            self._pan = (e.x, e.y)
            self.auto_fit = False
        self._dirty = True

    def _on_release(self, e):
        if not self._moved:
            self._select(self._press_node)
        self._drag = self._pan = self._press_node = None

    def _on_double(self, e):
        ip = self._node_at(e.x, e.y)
        self._drag = self._pan = self._press_node = None
        if ip:
            n = self.nodes[ip]
            n["pinned"] = not n["pinned"]
            self.alpha = max(self.alpha, 0.4)
            self._select(ip)
            self._style_dirty = True

    def _on_motion(self, e):
        self._mouse = (e.x, e.y)
        ip = self._node_at(e.x, e.y)
        if ip != self.hover:
            self.hover = ip
            self.config(cursor="hand2" if ip else "")
            self._style_dirty = True
        self._dirty = True

    def _on_leave(self, _e):
        self.hover = None
        self._style_dirty = self._dirty = True

    def _on_wheel(self, e):
        up = getattr(e, "num", 0) == 4 or getattr(e, "delta", 0) > 0
        new = max(0.2, min(5.0, self.t_scale * (1.2 if up else 1 / 1.2)))
        f = new / self.t_scale
        self.t_ox = e.x - (e.x - self.t_ox) * f      
        self.t_oy = e.y - (e.y - self.t_oy) * f
        self.t_scale = new
        self.auto_fit = False
        self._dirty = True

    def _select(self, ip):
        self.selected = ip
        self._style_dirty = self._dirty = True
        if self.on_select:
            self.on_select(ip)

    
    def _physics(self):
        nodes = list(self.nodes.values())
        for i, a in enumerate(nodes):
            ax, ay = a["x"], a["y"]
            for b in nodes[i + 1:]:
                dx, dy = ax - b["x"], ay - b["y"]
                d2 = dx * dx + dy * dy
                if d2 > REPEL_RANGE2:
                    continue
                if d2 < 4:
                    dx, dy, d2 = random.uniform(-2, 2), random.uniform(-2, 2), 4.0
                d = math.sqrt(d2)
                f = min(REPULSION / d2, 6.0)
                fx, fy = f * dx / d, f * dy / d
                a["vx"] += fx; a["vy"] += fy
                b["vx"] -= fx; b["vy"] -= fy
        for (u, v), _e in self.edges.items():
            a, b = self.nodes[u], self.nodes[v]
            dx, dy = b["x"] - a["x"], b["y"] - a["y"]
            d = math.hypot(dx, dy) or 1.0
            f = SPRING * (d - LINK_LEN)
            fx, fy = f * dx / d, f * dy / d
            a["vx"] += fx; a["vy"] += fy
            b["vx"] -= fx; b["vy"] -= fy
        k = self.alpha
        for ip, n in self.nodes.items():
            if n["pinned"] or ip == self._drag:
                n["vx"] = n["vy"] = 0.0
                continue
            n["vx"] = (n["vx"] - GRAVITY * n["x"]) * DAMPING
            n["vy"] = (n["vy"] - GRAVITY * n["y"]) * DAMPING
            sp = math.hypot(n["vx"], n["vy"])
            if sp > MAX_SPEED:
                n["vx"] *= MAX_SPEED / sp
                n["vy"] *= MAX_SPEED / sp
            n["x"] += n["vx"] * k
            n["y"] += n["vy"] * k

    
    def _tick(self):
        try:
            if self.winfo_ismapped():
                self._n += 1
                changed = False
                if self.nodes and not self.frozen and self.alpha > ALPHA_MIN:
                    self._physics()
                    self.alpha *= COOLING
                    changed = True
                if self.auto_fit and self.nodes and self._n % 6 == 0 and (changed or self._dirty):
                    self._fit_targets()
                if (abs(self.t_scale - self.scale) > 1e-3 or abs(self.t_ox - self.ox) > 0.3
                        or abs(self.t_oy - self.oy) > 0.3):
                    self.scale += (self.t_scale - self.scale) * 0.25   
                    self.ox += (self.t_ox - self.ox) * 0.25
                    self.oy += (self.t_oy - self.oy) * 0.25
                    changed = True
                if changed or self._dirty or self._style_dirty:
                    self._render()
        except tk.TclError:
            return                      
        self.after(self.FRAME_MS, self._tick)

    def _render(self):
        nodes, edges = self.nodes, self.edges
        restyle = self._style_dirty or self._n % 10 == 0
        focus = self.hover or self.selected
        near = (self.adj[focus] | {focus}) if focus in nodes else None
        maxb = max((n["bytes"] for n in nodes.values()), default=1) or 1
        busiest = set(sorted(nodes, key=lambda k: nodes[k]["bytes"], reverse=True)[:LABEL_TOP])
        show_all = self.scale >= 1.35

        for ip, n in nodes.items():
            n["r"] = 7 + 15 * math.sqrt(n["bytes"] / maxb)
            sx, sy = self._to_screen(n["x"], n["y"])
            r = max(3.0, n["r"] * self.scale)
            self.coords(n["g2"], sx - r * 2.2, sy - r * 2.2, sx + r * 2.2, sy + r * 2.2)
            self.coords(n["g1"], sx - r * 1.55, sy - r * 1.55, sx + r * 1.55, sy + r * 1.55)
            self.coords(n["body"], sx - r, sy - r, sx + r, sy + r)
            self.coords(n["lab"], sx, sy + r + 3)
            if restyle:
                dim = near is not None and ip not in near
                col = mix(n["col"], PLOT_BG, 0.7) if dim else n["col"]
                self.itemconfig(n["body"], fill=col,
                                outline=YELLOW if n["pinned"] else ("#ffffff" if not dim else GRID),
                                width=3 if ip == self.selected else (2 if n["pinned"] or ip == self.hover else 1))
                self.itemconfig(n["g1"], fill=mix(n["col"], PLOT_BG, 0.93 if dim else 0.78))
                self.itemconfig(n["g2"], fill=mix(n["col"], PLOT_BG, 0.96 if dim else 0.90))
                show = (not dim) and (ip in busiest or show_all or near is not None)
                self.itemconfig(n["lab"], state="normal" if show else "hidden")

        wmax = max((e["w"] for e in edges.values()), default=1)
        for (u, v), e in edges.items():
            a, b = nodes[u], nodes[v]
            x1, y1 = self._to_screen(a["x"], a["y"])
            x2, y2 = self._to_screen(b["x"], b["y"])
            self.coords(e["item"], x1, y1, x2, y2)
            if restyle:
                t = e["w"] / wmax
                if near is not None:
                    hot = u == focus or v == focus
                    col = "#b8ffff" if hot else mix(LIME, PLOT_BG, 0.88)
                    wid = 1.5 + 3 * t + (1 if hot else 0)
                else:
                    col, wid = mix(LIME, PLOT_BG, 0.72 - 0.5 * t), 1 + 3 * t
                self.itemconfig(e["item"], fill=col, width=wid)

        title = f"LIVE NETWORK MAP  //  {len(nodes)} hosts  {len(edges)} links"
        self.itemconfig(self.title_id, text=title + ("   [FROZEN]" if self.frozen else ""))
        self.itemconfig(self.empty_id, state="hidden" if nodes else "normal")
        self._update_tip()
        self._dirty = self._style_dirty = False

    def _update_tip(self):
        n = self.nodes.get(self.hover)
        if not n:
            self.itemconfig("tip", state="hidden")
            return
        text = (f"{self.hover}\n"
                f"type : {'LAN' if n['private'] else 'INTERNET'}\n"
                f"pkts : {n['pkts']}\n"
                f"data : {human_bytes(n['bytes'])}\n"
                f"links: {len(self.adj[self.hover])}"
                + ("\n[pinned - dbl-click to release]" if n["pinned"] else ""))
        self.itemconfig(self.tip_tx, text=text, state="normal")
        mx, my = self._mouse
        self.coords(self.tip_tx, mx + 16, my + 14)
        x1, y1, x2, y2 = self.bbox(self.tip_tx)
        shift = min(0, self.winfo_width() - x2 - 14)            
        if shift:
            self.move(self.tip_tx, shift, 0)
            x1, y1, x2, y2 = self.bbox(self.tip_tx)
        self.coords(self.tip_bg, x1 - 6, y1 - 4, x2 + 6, y2 + 4)
        self.itemconfig(self.tip_bg, state="normal")
        self.tag_raise("tip")



#  Main application
class PacketDashboard:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("NETWORK MONITOR // Packet Analyzer")
        root.geometry("1360x860")
        root.minsize(1100, 700)
        root.configure(bg=BG)

        self.sniffer = None
        self.q = queue.Queue()
        self.packets, self.records = [], []
        self.start_time = None
        self.proto_count, self.talkers = Counter(), Counter()
        self.total_bytes = 0
        self.last_count = 0
        self.led_on = False

        # port-scan 
        self.syn_ports = defaultdict(set)
        self.alerted = set()

        self._apply_theme()
        self._build_ui()
        self.root.after(POLL_MS, self._poll_queue)
        self.root.after(STATS_MS, self._refresh_stats)
        self.root.after(500, self._blink)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    #theme
    def _apply_theme(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure(".", background=BG, foreground=FG, fieldbackground=PANEL2,
                    bordercolor=GRID, lightcolor=GRID, darkcolor=GRID,
                    troughcolor=BG, font=FONT)
        s.configure("TFrame", background=BG)
        s.configure("TLabel", background=BG, foreground=FG)
        s.configure("Title.TLabel", foreground=CYAN, font=("Consolas", 18, "bold"))
        s.configure("Sub.TLabel", foreground=MAGENTA, font=("Consolas", 9))
        s.configure("Head.TLabel", foreground=CYAN, font=("Consolas", 11, "bold"))
        s.configure("Stat.TLabel", foreground=LIME, font=("Consolas", 11))

        s.configure("TButton", background=PANEL2, foreground=CYAN, bordercolor=CYAN,
                    focuscolor=PANEL2, padding=(10, 4), font=FONT_B)
        s.map("TButton", background=[("active", CYAN), ("disabled", PANEL)],
              foreground=[("active", BG), ("disabled", DIM)])
        s.configure("Go.TButton", foreground=LIME, bordercolor=LIME)
        s.map("Go.TButton", background=[("active", LIME), ("disabled", PANEL)],
              foreground=[("active", BG), ("disabled", DIM)])
        s.configure("Stop.TButton", foreground=RED, bordercolor=RED)
        s.map("Stop.TButton", background=[("active", RED), ("disabled", PANEL)],
              foreground=[("active", BG), ("disabled", DIM)])

        s.configure("TEntry", fieldbackground=PANEL2, foreground=CYAN,
                    insertcolor=CYAN, bordercolor=GRID)
        s.configure("TCombobox", fieldbackground=PANEL2, foreground=CYAN,
                    background=PANEL2, arrowcolor=CYAN, bordercolor=GRID)
        s.map("TCombobox", fieldbackground=[("readonly", PANEL2)],
              foreground=[("readonly", CYAN)],
              selectbackground=[("readonly", PANEL2)],
              selectforeground=[("readonly", CYAN)])
        self.root.option_add("*TCombobox*Listbox.background", PANEL2)
        self.root.option_add("*TCombobox*Listbox.foreground", CYAN)
        self.root.option_add("*TCombobox*Listbox.selectBackground", CYAN)
        self.root.option_add("*TCombobox*Listbox.selectForeground", BG)

        s.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG,
                    rowheight=22, bordercolor=GRID, font=FONT)
        s.configure("Treeview.Heading", background=PANEL2, foreground=CYAN,
                    relief="flat", font=FONT_B)
        s.map("Treeview", background=[("selected", "#143a52")],
              foreground=[("selected", "#ffffff")])
        s.map("Treeview.Heading", background=[("active", GRID)])

        s.configure("TNotebook", background=BG, bordercolor=GRID, tabmargins=(2, 4, 2, 0))
        s.configure("TNotebook.Tab", background=PANEL, foreground=DIM,
                    padding=(14, 5), font=FONT_B)
        s.map("TNotebook.Tab", background=[("selected", PANEL2)],
              foreground=[("selected", CYAN)])

        s.configure("TScrollbar", background=PANEL2, troughcolor=BG,
                    arrowcolor=CYAN, bordercolor=GRID)
        s.configure("TPanedwindow", background=BG)

    #  User interface 
    def _build_ui(self):
        # ---- header banner
        head = ttk.Frame(self.root, padding=(10, 8, 10, 2))
        head.pack(fill="x")
        ttk.Label(head, text="◢◤ NETWORK MONITOR", style="Title.TLabel").pack(side="left")
        ttk.Label(head, text="  //=== PACKET ANALYZER ===// ",
                  style="Sub.TLabel").pack(side="left", pady=(8, 0))
        self.led = tk.Label(head, text="● STANDBY", bg=BG, fg=DIM, font=("Consolas", 11, "bold"))
        self.led.pack(side="right")

        tk.Frame(self.root, bg=CYAN, height=1).pack(fill="x", padx=10)

        # ---- toolbar
        bar = ttk.Frame(self.root, padding=(10, 8))
        bar.pack(fill="x")
        ttk.Label(bar, text="IFACE>").pack(side="left")
        self.iface_var = tk.StringVar()
        ifaces = self._list_interfaces()
        self.iface_box = ttk.Combobox(bar, textvariable=self.iface_var, values=ifaces,
                                      width=28, state="readonly")
        if ifaces:
            self.iface_box.current(0)
        self.iface_box.pack(side="left", padx=(4, 12))

        ttk.Label(bar, text="BPF>").pack(side="left")
        self.bpf_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.bpf_var, width=18).pack(side="left", padx=(4, 12))

        self.start_btn = ttk.Button(bar, text="▶ START", style="Go.TButton", command=self.start_capture)
        self.start_btn.pack(side="left", padx=2)
        self.stop_btn = ttk.Button(bar, text="■ STOP", style="Stop.TButton",
                                   command=self.stop_capture, state="disabled")
        self.stop_btn.pack(side="left", padx=2)
        ttk.Button(bar, text="CLEAR", command=self.clear).pack(side="left", padx=2)
        ttk.Button(bar, text="SAVE", command=self.save_pcap).pack(side="left", padx=2)
        ttk.Button(bar, text="OPEN", command=self.open_pcap).pack(side="left", padx=2)

        ttk.Label(bar, text="   FILTER>").pack(side="left")
        self.filter_var = tk.StringVar()
        fe = ttk.Entry(bar, textvariable=self.filter_var, width=20)
        fe.pack(side="left", padx=4)
        fe.bind("<Return>", lambda e: self._reapply_filter())
        ttk.Button(bar, text="APPLY", command=self._reapply_filter).pack(side="left")

        # ---- status bar (packed first so it stays at the bottom)
        self.status = tk.StringVar(value="Ready. Select an interface and press START (admin/root required).")
        tk.Label(self.root, textvariable=self.status, anchor="w", bg=PANEL, fg=LIME,
                 font=FONT, padx=8, pady=3).pack(fill="x", side="bottom")

        # ---- main area: views (left) + stats (right)
        main = ttk.PanedWindow(self.root, orient="horizontal")
        main.pack(fill="both", expand=True, padx=8, pady=(0, 6))

        self.view_nb = ttk.Notebook(main)
        main.add(self.view_nb, weight=4)

        # ===== tab 1: packet feed
        feed = ttk.PanedWindow(self.view_nb, orient="vertical")
        self.view_nb.add(feed, text="  PACKET FEED  ")

        table_frame = ttk.Frame(feed)
        cols = ("no", "time", "src", "dst", "proto", "len", "info")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        widths = {"no": 60, "time": 80, "src": 160, "dst": 160, "proto": 70, "len": 60, "info": 420}
        heads = {"no": "No.", "time": "Time(s)", "src": "Source", "dst": "Destination",
                 "proto": "Proto", "len": "Len", "info": "Info"}
        for c in cols:
            self.tree.heading(c, text=heads[c])
            self.tree.column(c, width=widths[c], anchor="w", stretch=(c == "info"))
        for proto, color in PROTO_COLORS.items():
            self.tree.tag_configure(proto, foreground=color)
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        feed.add(table_frame, weight=3)

        nb = ttk.Notebook(feed)
        feed.add(nb, weight=2)

        layers_frame = ttk.Frame(nb)
        self.detail_tree = ttk.Treeview(layers_frame, columns=("value",), show="tree headings")
        self.detail_tree.heading("#0", text="Layer / Field")
        self.detail_tree.heading("value", text="Value")
        self.detail_tree.column("#0", width=260)
        self.detail_tree.column("value", width=500)
        self.detail_tree.tag_configure("layer", foreground=MAGENTA)
        dsb = ttk.Scrollbar(layers_frame, orient="vertical", command=self.detail_tree.yview)
        self.detail_tree.configure(yscrollcommand=dsb.set)
        self.detail_tree.pack(side="left", fill="both", expand=True)
        dsb.pack(side="right", fill="y")
        nb.add(layers_frame, text=" PROTOCOL LAYERS ")

        self.hex_text = self._make_text(nb, LIME)
        nb.add(self.hex_text.master, text=" HEX DUMP ")
        self.payload_text = self._make_text(nb, CYAN)
        nb.add(self.payload_text.master, text=" PAYLOAD ")

        # ===== tab 2: interactive network map (own canvas; keeps running after STOP)
        map_frame = ttk.Frame(self.view_nb)
        self.view_nb.add(map_frame, text="  NETWORK MAP  ")
        self.netmap = NetworkMap(map_frame, on_select=self._on_map_select)
        mbar = ttk.Frame(map_frame, padding=(6, 6, 6, 2))
        mbar.pack(fill="x")
        ttk.Button(mbar, text="⌖ FIT", command=self.netmap.fit).pack(side="left", padx=2)
        ttk.Button(mbar, text="⟳ RE-LAYOUT", command=self.netmap.relayout).pack(side="left", padx=2)
        ttk.Button(mbar, text="UNPIN ALL", command=self.netmap.unpin_all).pack(side="left", padx=2)
        self.freeze_btn = ttk.Button(mbar, text="❚❚ FREEZE", command=self._toggle_freeze)
        self.freeze_btn.pack(side="left", padx=2)
        self.map_pkts_btn = ttk.Button(mbar, text="PACKETS ▶", command=self._map_show_packets,
                                       state="disabled")
        self.map_pkts_btn.pack(side="left", padx=2)
        self.map_hint = " "
        self.map_info = tk.StringVar(value=self.map_hint)
        tk.Label(map_frame, textvariable=self.map_info, bg=BG, fg=LIME, font=FONT,
                 anchor="w", padx=10).pack(fill="x")
        self.netmap.pack(fill="both", expand=True, padx=4, pady=(2, 4))

        # ---- right: statistics / alerts
        right = ttk.Frame(main, padding=(10, 0))
        main.add(right, weight=1)

        ttk.Label(right, text="▌LIVE STATS", style="Head.TLabel").pack(anchor="w", pady=(4, 4))
        self.lbl_total = ttk.Label(right, text="Packets : 0", style="Stat.TLabel")
        self.lbl_bytes = ttk.Label(right, text="Bytes   : 0", style="Stat.TLabel")
        self.lbl_pps = ttk.Label(right, text="Rate    : 0 pkt/s", style="Stat.TLabel")
        for lbl in (self.lbl_total, self.lbl_bytes, self.lbl_pps):
            lbl.pack(anchor="w")

        ttk.Label(right, text="\n▌PROTOCOLS", style="Head.TLabel").pack(anchor="w")
        self.chart = tk.Canvas(right, width=280, height=230, bg=PLOT_BG,
                               highlightthickness=1, highlightbackground=GRID)
        self.chart.pack(fill="x", pady=4)

        ttk.Label(right, text="▌TOP TALKERS", style="Head.TLabel").pack(anchor="w", pady=(8, 2))
        self.talker_list = tk.Listbox(right, height=7, font=("Consolas", 9), bg=PLOT_BG, fg=CYAN,
                                      highlightthickness=1, highlightbackground=GRID,
                                      relief="flat", selectbackground=CYAN, selectforeground=BG)
        self.talker_list.pack(fill="x")

        ttk.Label(right, text="▌THREAT ALERTS", foreground=RED,
                  font=("Consolas", 11, "bold")).pack(anchor="w", pady=(10, 2))
        self.alert_list = tk.Listbox(right, height=6, font=("Consolas", 9), bg=PLOT_BG, fg=RED,
                                     highlightthickness=1, highlightbackground=RED,
                                     relief="flat", selectbackground=RED, selectforeground=BG)
        self.alert_list.pack(fill="x")

    @staticmethod
    def _make_text(parent, fg):
        frame = ttk.Frame(parent)
        txt = tk.Text(frame, font=("Consolas", 10), wrap="none", state="disabled",
                      bg=PLOT_BG, fg=fg, insertbackground=fg, relief="flat",
                      highlightthickness=0, selectbackground=GRID)
        sb = ttk.Scrollbar(frame, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        txt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return txt

    @staticmethod
    def _list_interfaces():
        try:
            from scapy.interfaces import get_working_ifaces
            names = [i.name for i in get_working_ifaces()]
            if names:
                return names
        except Exception:
            pass
        try:
            return get_if_list()
        except Exception:
            return []

    def _blink(self):
        if self.sniffer is not None:
            self.led_on = not self.led_on
            self.led.config(text="● LIVE", fg=RED if self.led_on else "#7a1a2c")
        else:
            self.led.config(text="● STANDBY", fg=DIM)
        self.root.after(500, self._blink)

    # ----------------------------- capture control ------------------------- #
    def start_capture(self):
        iface = self.iface_var.get() or None
        bpf = self.bpf_var.get().strip() or None
        if self.start_time is None:
            self.start_time = time.time()
        try:
            self.sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=self.q.put, store=False)
            self.sniffer.start()
        except Exception as exc:
            self.sniffer = None
            messagebox.showerror("Capture error",
                                 f"Could not start capture:\n{exc}\n\n"
                                 "Run as Administrator/root and make sure Npcap/libpcap is installed.")
            return
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status.set(f"> INTERCEPTING on {iface or 'default interface'}"
                        + (f"  |  filter: {bpf}" if bpf else ""))

    def stop_capture(self):
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status.set(f"> HALTED. {len(self.packets)} packets in buffer.")

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.packets.clear()
        self.records.clear()
        self.proto_count.clear()
        self.talkers.clear()
        self.total_bytes = 0
        self.last_count = 0
        self.start_time = time.time() if self.sniffer else None
        self.syn_ports.clear()
        self.alerted.clear()
        self.alert_list.delete(0, "end")
        self.netmap.reset()
        self._clear_details()
        self._refresh_stats(reschedule=False)

    # ----------------------------- queue processing ------------------------ #
    def _poll_queue(self):
        processed = 0
        while processed < 300:
            try:
                pkt = self.q.get_nowait()
            except queue.Empty:
                break
            self._add_packet(pkt)
            processed += 1
        self.root.after(POLL_MS, self._poll_queue)

    def _add_packet(self, pkt):
        if len(self.packets) >= MAX_PACKETS:
            self.stop_capture()
            self.status.set(f"> BUFFER FULL ({MAX_PACKETS} packets). Save or clear.")
            return
        ts = float(getattr(pkt, "time", time.time())) - (self.start_time or time.time())
        rec = parse_packet(pkt)
        rec["no"] = len(self.packets) + 1
        rec["time"] = f"{max(ts, 0):.4f}"
        rec["len"] = len(pkt)
        self.packets.append(pkt)
        self.records.append(rec)

        self.proto_count[rec["proto"]] += 1
        self.talkers[rec["src"]] += 1
        self.total_bytes += rec["len"]

        self._update_graph(rec)
        self._detect_scan(pkt, rec)

        if self._matches_filter(rec):
            self._insert_row(rec)

    def _insert_row(self, rec):
        tag = rec["proto"] if rec["proto"] in PROTO_COLORS else "OTHER"
        self.tree.insert("", "end", iid=str(rec["no"] - 1),
                         values=(rec["no"], rec["time"], rec["src"], rec["dst"],
                                 rec["proto"], rec["len"], rec["info"]),
                         tags=(tag,))
        if self.sniffer is not None:
            self.tree.yview_moveto(1.0)

    # ----------------------------- threat detection ------------------------ #
    def _detect_scan(self, pkt, rec):
        if not (pkt.haslayer(TCP) and rec["ip"]):
            return
        if str(pkt[TCP].flags) != "S":      # SYN only (connection attempt)
            return
        ports = self.syn_ports[rec["src"]]
        ports.add(pkt[TCP].dport)
        if len(ports) >= SCAN_THRESHOLD and rec["src"] not in self.alerted:
            self.alerted.add(rec["src"])
            msg = f"[{time.strftime('%H:%M:%S')}] PORT SCAN? {rec['src']} -> {len(ports)} ports"
            self.alert_list.insert(0, msg)
            self.status.set("> !! " + msg)

    # ----------------------------- network map ----------------------------- #
    def _update_graph(self, rec):
        if rec["ip"]:
            self.netmap.add_packet(rec["src"], rec["dst"], rec["len"])

    def _on_map_select(self, ip):
        self.map_pkts_btn.config(state="normal" if ip else "disabled")
        self._update_map_info()

    def _update_map_info(self):
        ip = self.netmap.selected
        info = self.netmap.node_info(ip) if ip else None
        if info:
            self.map_info.set(f"{ip}  |  {info['kind']}  |  {info['pkts']} pkts  |  "
                              f"{human_bytes(info['bytes'])}  |  {info['links']} links"
                              + ("  |  PINNED" if info["pinned"] else ""))
        else:
            self.map_info.set(self.map_hint)

    def _toggle_freeze(self):
        frozen = self.netmap.toggle_freeze()
        self.freeze_btn.config(text="▶ RESUME" if frozen else "❚❚ FREEZE")

    def _map_show_packets(self):
        ip = self.netmap.selected
        if not ip:
            return
        self.filter_var.set(ip)
        self._reapply_filter()
        self.view_nb.select(0)
        self.status.set(f"> FILTER: showing packets for {ip}  (clear the FILTER box to see all)")

    # ----------------------------- filtering ------------------------------- #
    def _matches_filter(self, rec):
        term = self.filter_var.get().strip().lower()
        if not term:
            return True
        hay = f"{rec['src']} {rec['dst']} {rec['proto']} {rec['info']} {rec['sport']} {rec['dport']}".lower()
        return all(part in hay for part in term.split())

    def _reapply_filter(self):
        self.tree.delete(*self.tree.get_children())
        for rec in self.records:
            if self._matches_filter(rec):
                self._insert_row(rec)

    # ----------------------------- details view ---------------------------- #
    def _clear_details(self):
        self.detail_tree.delete(*self.detail_tree.get_children())
        for t in (self.hex_text, self.payload_text):
            self._set_text(t, "")

    @staticmethod
    def _set_text(widget, content):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.config(state="disabled")

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        pkt = self.packets[int(sel[0])]
        self.detail_tree.delete(*self.detail_tree.get_children())
        for name, rows in layer_tree(pkt):
            parent = self.detail_tree.insert("", "end", text="▼ " + name, open=True, tags=("layer",))
            for field, value in rows:
                self.detail_tree.insert(parent, "end", text=field, values=(value,))
        self._set_text(self.hex_text, hex_dump(bytes(pkt)))
        self._set_text(self.payload_text, payload_text(pkt))

    # ----------------------------- statistics ------------------------------ #
    def _refresh_stats(self, reschedule=True):
        count = len(self.packets)
        pps = count - self.last_count
        self.last_count = count
        self.lbl_total.config(text=f"Packets : {count}")
        self.lbl_bytes.config(text=f"Bytes   : {self.total_bytes:,}")
        self.lbl_pps.config(text=f"Rate    : {max(pps, 0)} pkt/s")
        self._draw_chart()
        self._update_map_info()

        self.talker_list.delete(0, "end")
        for ip, n in self.talkers.most_common(7):
            self.talker_list.insert("end", f"{ip[:30]:<30} {n}")

        if reschedule:
            self.root.after(STATS_MS, self._refresh_stats)

    def _draw_chart(self):
        c = self.chart
        c.delete("all")
        data = self.proto_count.most_common(8)
        if not data:
            c.create_text(140, 115, text="NO DATA", fill=DIM, font=FONT)
            return
        top = max(n for _, n in data)
        bar_h, gap, left, right_pad = 20, 8, 56, 44
        width = int(c.winfo_width() or 280)
        for i, (proto, n) in enumerate(data):
            y = 10 + i * (bar_h + gap)
            w = (width - left - right_pad) * n / top
            color = PROTO_COLORS.get(proto, "#8899aa")
            c.create_text(6, y + bar_h / 2, text=proto, anchor="w", fill=color, font=("Consolas", 9, "bold"))
            c.create_rectangle(left, y, left + max(w, 2), y + bar_h, fill=color, outline="")
            c.create_text(left + w + 5, y + bar_h / 2, text=str(n), anchor="w", fill=FG, font=("Consolas", 9))

    # files input output 
    def save_pcap(self):
        if not self.packets:
            messagebox.showinfo("Nothing to save", "No packets captured yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if path:
            wrpcap(path, self.packets)
            self.status.set(f"> SAVED {len(self.packets)} packets to {path}")

    def open_pcap(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")])
        if not path:
            return
        self.stop_capture()
        self.clear()
        try:
            pkts = rdpcap(path)
        except Exception as exc:
            messagebox.showerror("Open error", str(exc))
            return
        if len(pkts):
            self.start_time = float(pkts[0].time)
        for p in pkts[:MAX_PACKETS]:
            self._add_packet(p)
        self._refresh_stats(reschedule=False)
        self.netmap.fit()
        self.status.set(f"> LOADED {len(self.packets)} packets from {path}")

    def _on_close(self):
        self.stop_capture()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    PacketDashboard(root)
    root.mainloop()