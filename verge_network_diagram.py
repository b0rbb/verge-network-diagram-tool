#!/usr/bin/env python3
"""
VergeOS Network Diagram Generator

Generates 2D network diagrams showing External, Internal, DMZ, and Core
networks, their backing Physical Networks, and Node NIC connections.
Exports to PDF, PNG, or SVG.
"""

import argparse
import json
import sys
import time
from collections import defaultdict

import graphviz
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FONT = "Helvetica"

TYPE_LABELS = {
    "external": "External",
    "internal": "Internal",
    "dmz": "DMZ",
    "core": "Core",
}

THEMES = {
    "light": {
        "bg": "white",
        "title_color": "black",
        "text": "#222222",
        "text_secondary": "#555555",
        "cluster_fill": "#f0f4f8",
        "cluster_border": "#cccccc",
        "overlay_fill": "#faf5ff",
        "overlay_border": "#9b59b6",
        "overlay_label_color": None,
        "edge_main": "#888888",
        "edge_compact": "#aaaaaa",
        "edge_route": "#e74c3c",
        "route_colors": [
            "#e74c3c", "#2980b9", "#27ae60", "#8e44ad",
            "#e67e22", "#16a085", "#c0392b", "#2c3e50",
            "#d35400", "#1abc9c", "#7d3c98", "#2e86c1",
        ],
        "legend_header_bg": "#333333",
        "legend_body_bg": "white",
        "legend_text": None,
        "type_colors": {
            "external": {"header": "#2d6a4f", "body": "#d8f3dc", "compact": "#b7e4c7"},
            "internal": {"header": "#6a2d6a", "body": "#f3d8f3", "compact": "#e4b7e4"},
            "dmz": {"header": "#6a4a2d", "body": "#f3e8d8", "compact": "#e4d4b7"},
            "core": {"header": "#2d4a6a", "body": "#d8e8f3", "compact": "#b7d4e4"},
        },
        "physical": {"header": "#4a90d9", "body": "#e8f0fe"},
        "services": {"bg": "#fff3cd", "fg": "#856404"},
        "routes": {"bg": "#cce5ff", "fg": "#004085"},
        "trunk_grid_bg": "#e9ecef",
        "trunk_grid_text": None,
    },
    "dark": {
        "bg": "#0a1628",
        "title_color": "#e0e8f0",
        "text": "#d0d8e0",
        "text_secondary": "#8899aa",
        "cluster_fill": "#12243d",
        "cluster_border": "#2a4060",
        "overlay_fill": "#1a1230",
        "overlay_border": "#7b4fbf",
        "overlay_label_color": "#c8a0f0",
        "edge_main": "#5588aa",
        "edge_compact": "#446688",
        "edge_route": "#ff6b6b",
        "route_colors": [
            "#ff6b6b", "#5dade2", "#58d68d", "#bb8fce",
            "#f0b27a", "#48c9b0", "#ec7063", "#85c1e9",
            "#e59866", "#76d7c4", "#c39bd3", "#7fb3d8",
        ],
        "legend_header_bg": "#1a2a44",
        "legend_body_bg": "#0f1e33",
        "legend_text": "#c0ccd8",
        "type_colors": {
            "external": {"header": "#1b8a5a", "body": "#0f3d2a", "compact": "#164d33"},
            "internal": {"header": "#8a3d8a", "body": "#3d1a3d", "compact": "#4d2050"},
            "dmz": {"header": "#a07030", "body": "#3d2a14", "compact": "#4d3520"},
            "core": {"header": "#3a7abf", "body": "#142a44", "compact": "#1a3555"},
        },
        "physical": {"header": "#3a80cc", "body": "#142a44"},
        "services": {"bg": "#3d3520", "fg": "#f0d080"},
        "routes": {"bg": "#1a2a44", "fg": "#70b0ff"},
        "trunk_grid_bg": "#1a2a3d",
        "trunk_grid_text": "#8899aa",
    },
}


def get_theme(name="light"):
    return THEMES.get(name, THEMES["light"])


class VergeAPIClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip("/")
        self.api_url = f"{self.base_url}/api/v4"
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = False

    def get(self, endpoint, params=None):
        resp = self.session.get(f"{self.api_url}/{endpoint}", params=params)
        resp.raise_for_status()
        return resp.json()

    def get_networks(self, type_filter=None):
        fields = (
            "$key,name,type,layer2_type,layer2_id,interface_vnet,"
            "ipaddress,network,gateway,dhcp_enabled,"
            "mtu,description,ipaddress_type,hostname,domain"
        )
        params = {"fields": fields}
        if type_filter:
            conditions = " or ".join(f"type eq '{t}'" for t in type_filter)
            params["filter"] = conditions
        else:
            params["filter"] = "type ne 'physical'"
        return self.get("vnets", params)

    def get_physical_networks(self):
        return self.get(
            "vnets",
            {
                "fields": "$key,name,type,layer2_type,layer2_id,interface_vnet,description",
                "filter": "type eq 'physical'",
            },
        )

    def get_all_networks(self):
        return self.get("vnets", {"fields": "$key,name,type"})

    def get_nodes(self):
        return self.get("nodes", {"fields": "$key,name,machine"})

    def get_machine_nics_for_vnet(self, vnet_key):
        return self.get(
            "machine_nics",
            {
                "fields": "$key,name,machine,interface,vnet,driver,model,vendor",
                "filter": f"vnet eq {vnet_key}",
            },
        )

    def get_route_rules(self):
        return self.get(
            "vnet_rules",
            {
                "fields": "$key,vnet,name,action,direction,destination_ip,target_ip,enabled",
                "filter": "action eq 'route'",
            },
        )

    def get_wireguards(self):
        return self.get(
            "vnet_wireguards",
            {"fields": "$key,name,vnet,ip,listenport,enabled,endpoint_ip"},
        )

    def get_bgp_routers(self):
        return self.get("vnet_bgp_routers")

    def get_ipsecs(self):
        return self.get("vnet_ipsecs")

    def get_dns_zones(self):
        return self.get("vnet_dns_zones")

    def get_system_settings(self):
        rows = self.get("settings", {"fields": "key,value"})
        if isinstance(rows, dict):
            rows = rows.get("rows", rows.get("data", []))
        return {r.get("key"): r.get("value") for r in rows if r.get("key")}

    def run_whatsmyip(self, vnet_key, poll_tries=10, poll_interval=1.5):
        """Run the VergeOS 'whatsmyip' network diagnostic against a vnet and return
        the detected public (egress) IP. Returns None on failure."""
        resp = self.session.post(
            f"{self.api_url}/vnet_queries",
            json={"vnet": vnet_key, "query": "whatsmyip"},
        )
        resp.raise_for_status()
        key = resp.json().get("$key")
        if not key:
            return None
        result = None
        try:
            for _ in range(poll_tries):
                row = self.get(f"vnet_queries/{key}", {"fields": "all"})
                if row.get("status") == "complete":
                    result = (row.get("result") or "").strip()
                    break
                time.sleep(poll_interval)
        finally:
            try:
                self.session.delete(f"{self.api_url}/vnet_queries/{key}")
            except Exception:
                pass
        return result or None


def collect_data(client, type_filter=None):
    print("Fetching data from VergeOS API...")

    settings = client.get_system_settings()
    networks = client.get_networks(type_filter)
    phys_nets = client.get_physical_networks()
    all_nets = client.get_all_networks()
    nodes = client.get_nodes()
    routes = client.get_route_rules()
    wireguards = client.get_wireguards()
    bgp_routers = client.get_bgp_routers()
    ipsecs = client.get_ipsecs()
    dns_zones = client.get_dns_zones()

    net_by_key = {n["$key"]: n for n in all_nets}
    node_by_machine = {n["machine"]: n for n in nodes}

    phys_nics = {}
    for pn in phys_nets:
        nics = client.get_machine_nics_for_vnet(pn["$key"])
        host_nics = [n for n in nics if not n["name"].startswith("yb-")]
        phys_nics[pn["$key"]] = host_nics

    routes_by_vnet = defaultdict(list)
    for r in routes:
        if r.get("enabled"):
            routes_by_vnet[r["vnet"]].append(r)

    wg_by_vnet = defaultdict(list)
    for wg in wireguards:
        if wg.get("enabled"):
            wg_by_vnet[wg["vnet"]].append(wg)

    bgp_by_vnet = defaultdict(list)
    for bgp in bgp_routers:
        bgp_by_vnet[bgp.get("vnet", 0)].append(bgp)

    ipsec_by_vnet = defaultdict(list)
    for ips in ipsecs:
        ipsec_by_vnet[ips.get("vnet", 0)].append(ips)

    dns_by_vnet = defaultdict(list)
    for dz in dns_zones:
        dns_by_vnet[dz.get("vnet", 0)].append(dz)

    public_ip_by_vnet = {}
    for net in networks:
        if net.get("type") == "external":
            print(f"  Running 'whatsmyip' diagnostic on {net.get('name')}...")
            try:
                public_ip_by_vnet[net["$key"]] = client.run_whatsmyip(net["$key"])
            except Exception as e:
                print(f"    (whatsmyip failed: {e})")
                public_ip_by_vnet[net["$key"]] = None

    return {
        "cloud_name": settings.get("cloud_name", ""),
        "system_id": settings.get("system_id", ""),
        "public_ip_by_vnet": public_ip_by_vnet,
        "networks": networks,
        "phys_nets": phys_nets,
        "net_by_key": net_by_key,
        "node_by_machine": node_by_machine,
        "nodes": nodes,
        "phys_nics": phys_nics,
        "routes_by_vnet": routes_by_vnet,
        "wg_by_vnet": wg_by_vnet,
        "bgp_by_vnet": bgp_by_vnet,
        "ipsec_by_vnet": ipsec_by_vnet,
        "dns_by_vnet": dns_by_vnet,
    }


def is_bare_vlan(net, data):
    """A network with no IP, no services, and no routes — just a VLAN stub."""
    key = net["$key"]
    ip = net.get("ipaddress", "")
    network = net.get("network", "")
    has_services = (
        data["bgp_by_vnet"].get(key)
        or data["ipsec_by_vnet"].get(key)
        or data["dns_by_vnet"].get(key)
        or data["wg_by_vnet"].get(key)
        or net.get("dhcp_enabled")
    )
    has_routes = bool(data["routes_by_vnet"].get(key))
    return not ip and not network and not has_services and not has_routes


def format_route(route, net_by_key):
    dest = route.get("destination_ip", "")
    target = route.get("target_ip", "")

    if target.startswith("vnetkey:"):
        vnet_key = int(target.split(":")[1])
        target_net = net_by_key.get(vnet_key)
        if target_net:
            target = f"&rarr; {target_net['name']}"
        else:
            target = f"&rarr; vnet:{vnet_key}"
    else:
        target = f"&rarr; {target}"

    if dest == "default":
        return f"default {target}"
    elif dest.startswith("address:"):
        return f"{route.get('name', dest)} {target}"
    else:
        return f"{dest} {target}"


def build_service_list(vnet_key, data):
    services = []
    if data["bgp_by_vnet"].get(vnet_key):
        services.append("BGP")
    if data["ipsec_by_vnet"].get(vnet_key):
        services.append("IPSec")
    if data["dns_by_vnet"].get(vnet_key):
        services.append("DNS Server")
    for wg in data["wg_by_vnet"].get(vnet_key, []):
        port = wg.get("listenport", 51820)
        wg_ip = wg.get("ip", "")
        services.append(f"WireGuard ({wg_ip} :{port})")
    return services


def _font(size, color=None, bold=False):
    """Helper to build an opening <FONT> tag with consistent face."""
    parts = [f'FACE="{FONT}"', f'POINT-SIZE="{size}"']
    if color:
        parts.append(f'COLOR="{color}"')
    tag = "<FONT " + " ".join(parts) + ">"
    if bold:
        tag += "<B>"
    return tag


def _cfont(bold=False):
    """Close font tag, with optional bold close."""
    return ("</B>" if bold else "") + "</FONT>"


def build_compact_node(net, theme):
    """Small box: just name + VLAN ID or type tag."""
    net_type = net.get("type", "external")
    colors = theme["type_colors"].get(net_type, theme["type_colors"]["external"])
    type_label = TYPE_LABELS.get(net_type, net_type.title())
    txt = theme["text"]

    l2_type = net.get("layer2_type", "")
    l2_id = net.get("layer2_id", 0)
    if l2_type == "vlan" and l2_id:
        subtitle = f"VLAN {l2_id}"
    elif l2_type == "vxlan" and l2_id:
        subtitle = f"VXLAN {l2_id}"
    elif l2_type == "none":
        subtitle = "Native"
    else:
        subtitle = type_label

    return (
        f'<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="3">'
        f'<TR><TD BGCOLOR="{colors["compact"]}">'
        f'{_font(9, txt, bold=True)}{net["name"]}{_cfont(True)}'
        f"</TD></TR>"
        f'<TR><TD BGCOLOR="{colors["compact"]}">'
        f"{_font(8, txt)}{subtitle}{_cfont()}"
        f"</TD></TR>"
        f"</TABLE>>"
    )


def build_compact_grid(compact_nets, theme, cols=4):
    """Build a single HTML table node containing a grid of bare VLANs."""
    txt = theme["text"]
    grid_bg = theme["trunk_grid_bg"]
    grid_txt = theme.get("trunk_grid_text") or txt

    rows_html = ""
    for i in range(0, len(compact_nets), cols):
        chunk = compact_nets[i : i + cols]
        cells = ""
        for net in chunk:
            net_type = net.get("type", "external")
            colors = theme["type_colors"].get(net_type, theme["type_colors"]["external"])
            l2_type = net.get("layer2_type", "")
            l2_id = net.get("layer2_id", 0)
            if l2_type == "vlan" and l2_id:
                subtitle = f"VLAN {l2_id}"
            elif l2_type == "vxlan" and l2_id:
                subtitle = f"VXLAN {l2_id}"
            elif l2_type == "none":
                subtitle = "Native"
            else:
                subtitle = TYPE_LABELS.get(net_type, "")
            cells += (
                f'<TD BGCOLOR="{colors["compact"]}" CELLPADDING="4">'
                f'{_font(9, txt, bold=True)}{net["name"]}{_cfont(True)}<BR/>'
                f"{_font(7, txt)}{subtitle}{_cfont()}</TD>"
            )
        pad = cols - len(chunk)
        for _ in range(pad):
            cells += f'<TD BORDER="0" BGCOLOR="{grid_bg}"></TD>'
        rows_html += f"<TR>{cells}</TR>"

    return (
        f'<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="2" CELLPADDING="0">'
        f'<TR><TD COLSPAN="{cols}" BGCOLOR="{grid_bg}" CELLPADDING="4">'
        f"{_font(9, grid_txt)}<I>Trunk-only VLANs ({len(compact_nets)})</I>{_cfont()}</TD></TR>"
        f"{rows_html}"
        f"</TABLE>>"
    )


def build_detail_node(net, data, theme):
    """Full detail card with IP, services, routes."""
    net_type = net.get("type", "external")
    colors = theme["type_colors"].get(net_type, theme["type_colors"]["external"])
    type_label = TYPE_LABELS.get(net_type, net_type.title())
    key = net["$key"]
    txt = theme["text"]
    svc = theme["services"]
    rte = theme["routes"]

    info_lines = []

    l2_type = net.get("layer2_type", "")
    l2_id = net.get("layer2_id", 0)
    if l2_type == "vlan" and l2_id:
        info_lines.append(f"VLAN {l2_id}")
    elif l2_type == "vxlan" and l2_id:
        info_lines.append(f"VXLAN {l2_id}")
    elif l2_type == "none":
        info_lines.append("Native (untagged)")

    ip = net.get("ipaddress", "")
    network = net.get("network", "")
    ip_type = net.get("ipaddress_type", "")
    if ip:
        info_lines.append(f"IP: {ip}")
    if network:
        info_lines.append(f"Net: {network}")
    if ip_type and ip_type not in ("none", ""):
        info_lines.append(f"Type: {ip_type}")

    gw = net.get("gateway", "")
    if gw:
        info_lines.append(f"GW: {gw}")

    if net.get("mtu") and net["mtu"] != 1500:
        info_lines.append(f"MTU: {net['mtu']}")

    if net_type == "external":
        pub_ip = data.get("public_ip_by_vnet", {}).get(key)
        info_lines.append(f"Public IP: {pub_ip if pub_ip else '(not detected)'}")

    services = build_service_list(key, data)
    if net.get("dhcp_enabled"):
        services.append("DHCP Server")

    routes = data["routes_by_vnet"].get(key, [])
    route_lines = [format_route(r, data["net_by_key"]) for r in routes]

    hdr = colors["header"]

    info_rows = ""
    for line in info_lines:
        info_rows += (
            f'<TR><TD ALIGN="LEFT" BGCOLOR="{colors["body"]}">'
            f"{_font(10, txt)}{line}{_cfont()}</TD></TR>"
        )

    if services:
        svc_text = " | ".join(services)
        info_rows += (
            f'<TR><TD ALIGN="LEFT" BGCOLOR="{svc["bg"]}">'
            f'{_font(9, svc["fg"])}&#9881; {svc_text}{_cfont()}</TD></TR>'
        )

    if route_lines:
        info_rows += (
            f'<TR><TD ALIGN="LEFT" BGCOLOR="{rte["bg"]}">'
            f'{_font(9, rte["fg"])}Routes:{_cfont()}</TD></TR>'
        )
        for rl in route_lines:
            info_rows += (
                f'<TR><TD ALIGN="LEFT" BGCOLOR="{rte["bg"]}">'
                f'{_font(8, rte["fg"])}  {rl}{_cfont()}</TD></TR>'
            )

    return (
        f'<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="5">'
        f'<TR><TD BGCOLOR="{hdr}">'
        f'{_font(11, "white", bold=True)}{net["name"]}{_cfont(True)}</TD></TR>'
        f'<TR><TD BGCOLOR="{hdr}">'
        f'{_font(8, "white")}{type_label}{_cfont()}</TD></TR>'
        f"{info_rows}"
        f"</TABLE>>"
    )


def build_physical_node_label(pn, nics, node_by_machine, theme):
    """Build the label for a physical network cluster header."""
    phys = theme["physical"]
    txt = theme["text"]
    nic_rows = ""
    for nic in nics:
        node = node_by_machine.get(nic["machine"])
        node_name = node["name"] if node else f"machine:{nic['machine']}"
        nic_name = nic["name"]
        driver = nic.get("driver", "")
        nic_rows += (
            f'<TR><TD ALIGN="LEFT" BGCOLOR="{phys["body"]}">{_font(9, txt)}'
            f"{node_name}: {nic_name}"
            f"{(' (' + driver + ')') if driver else ''}"
            f"{_cfont()}</TD></TR>"
        )

    l2_info = ""
    if pn.get("layer2_type") == "bond":
        l2_info = " (Bonded)"
    elif pn.get("layer2_type") == "bond_slave":
        l2_info = " (Bond Member)"

    return (
        f'<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="6">'
        f'<TR><TD BGCOLOR="{phys["header"]}" COLSPAN="1">'
        f'{_font(12, "white", bold=True)}{pn["name"]}{l2_info}{_cfont(True)}</TD></TR>'
        f'<TR><TD BGCOLOR="{phys["body"]}">'
        f"{_font(10, txt)}{len(nics)} Node NIC(s){_cfont()}</TD></TR>"
        f"{nic_rows}"
        f"</TABLE>>"
    )


def build_legend(theme):
    """Build a color-coded legend/key for the diagram."""
    hdr_bg = theme["legend_header_bg"]
    body_bg = theme["legend_body_bg"]
    txt = theme.get("legend_text") or theme["text"]
    route_color = theme["edge_route"]

    rows = ""
    rows += (
        f'<TR><TD COLSPAN="2" BGCOLOR="{hdr_bg}" CELLPADDING="6">'
        f'{_font(12, "white", bold=True)}Legend{_cfont(True)}</TD></TR>'
    )

    for net_type, label in TYPE_LABELS.items():
        c = theme["type_colors"][net_type]
        rows += (
            f'<TR>'
            f'<TD BGCOLOR="{c["header"]}" WIDTH="20" HEIGHT="14"> </TD>'
            f'<TD ALIGN="LEFT" BGCOLOR="{body_bg}" CELLPADDING="4">'
            f"{_font(10, txt)}{label} Network{_cfont()}</TD>"
            f"</TR>"
        )

    phys = theme["physical"]
    rows += (
        f'<TR>'
        f'<TD BGCOLOR="{phys["header"]}" WIDTH="20" HEIGHT="14"> </TD>'
        f'<TD ALIGN="LEFT" BGCOLOR="{body_bg}" CELLPADDING="4">'
        f"{_font(10, txt)}Physical Network{_cfont()}</TD>"
        f"</TR>"
    )

    svc = theme["services"]
    rows += (
        f'<TR>'
        f'<TD BGCOLOR="{svc["bg"]}" WIDTH="20" HEIGHT="14"> </TD>'
        f'<TD ALIGN="LEFT" BGCOLOR="{body_bg}" CELLPADDING="4">'
        f"{_font(10, txt)}Services (WireGuard, DHCP, etc.){_cfont()}</TD>"
        f"</TR>"
    )

    rte = theme["routes"]
    rows += (
        f'<TR>'
        f'<TD BGCOLOR="{rte["bg"]}" WIDTH="20" HEIGHT="14"> </TD>'
        f'<TD ALIGN="LEFT" BGCOLOR="{body_bg}" CELLPADDING="4">'
        f"{_font(10, txt)}Routing Table{_cfont()}</TD>"
        f"</TR>"
    )

    rows += (
        f'<TR>'
        f'<TD BGCOLOR="{theme["trunk_grid_bg"]}" WIDTH="20" HEIGHT="14"> </TD>'
        f'<TD ALIGN="LEFT" BGCOLOR="{body_bg}" CELLPADDING="4">'
        f"{_font(10, txt)}Trunk-only VLAN (no IP){_cfont()}</TD>"
        f"</TR>"
    )

    route_colors = theme.get("route_colors", [route_color])
    color_samples = "".join(
        f'{_font(9, c)}&#9644;{_cfont()}' for c in route_colors[:4]
    )
    rows += (
        f"<TR>"
        f'<TD COLSPAN="2" ALIGN="LEFT" BGCOLOR="{body_bg}" CELLPADDING="4">'
        f'{color_samples} {_font(9, txt)}Inter-network route{_cfont()}</TD>'
        f"</TR>"
    )

    return (
        f'<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="0">'
        f"{rows}"
        f"</TABLE>>"
    )


def build_diagram(data, output_name, output_format, title=None, theme_name="light", layout="landscape"):
    print("Building diagram...")

    theme = get_theme(theme_name)
    portrait = layout == "portrait"
    grid_cols = 3 if portrait else 4

    main_title = title or data.get("cloud_name") or "VergeOS Network Topology"
    system_id = data.get("system_id") or ""
    tc = theme["title_color"]
    if system_id:
        graph_label = (
            f'<{_font(24, tc, bold=True)}{main_title}{_cfont(True)}<BR/>'
            f'{_font(6, tc)} {_cfont()}<BR/>'
            f'{_font(11, tc)}System ID: {system_id}{_cfont()}>'
        )
    else:
        graph_label = (
            f'<{_font(24, tc, bold=True)}{main_title}{_cfont(True)}>'
        )

    dot = graphviz.Digraph(
        name="VergeOS_Network_Diagram",
        format=output_format,
        engine="dot",
    )

    if portrait:
        dot.attr(
            rankdir="TB",
            label=graph_label,
            labelloc="t",
            fontname=FONT,
            fontcolor=theme["title_color"],
            bgcolor=theme["bg"],
            pad="0.5",
            nodesep="0.3",
            ranksep="0.6",
            compound="true",
            newrank="true",
        )
    else:
        dot.attr(
            rankdir="TB",
            label=graph_label,
            labelloc="t",
            fontname=FONT,
            fontcolor=theme["title_color"],
            bgcolor=theme["bg"],
            pad="0.5",
            nodesep="0.4",
            ranksep="0.8",
            compound="true",
        )

    dot.node_attr.update(fontname=FONT, fontcolor=theme["text"])
    dot.edge_attr.update(fontname=FONT)

    if not portrait:
        dot.node("legend", label=build_legend(theme), shape="plaintext")

    networks = data["networks"]
    phys_nets = data["phys_nets"]
    node_by_machine = data["node_by_machine"]
    phys_nics = data["phys_nics"]

    phys_by_key = {pn["$key"]: pn for pn in phys_nets}

    nets_by_phys = defaultdict(list)
    overlay_nets = []

    for net in networks:
        iface = net.get("interface_vnet")
        if iface and iface in phys_by_key:
            nets_by_phys[iface].append(net)
        else:
            overlay_nets.append(net)

    cluster_idx = 0
    cluster_anchor_ids = []

    phys_with_children = [pn for pn in phys_nets if nets_by_phys.get(pn["$key"])]
    phys_without_children = [pn for pn in phys_nets if not nets_by_phys.get(pn["$key"])]

    for pn in phys_with_children:
        pn_key = pn["$key"]
        child_nets = nets_by_phys[pn_key]
        nics = phys_nics.get(pn_key, [])

        cluster_idx += 1
        with dot.subgraph(name=f"cluster_{cluster_idx}") as sub:
            sub.attr(
                label="",
                style="rounded,filled",
                fillcolor=theme["cluster_fill"],
                color=theme["cluster_border"],
                penwidth="1.5",
                margin="16",
            )

            pn_id = f"phys_{pn_key}"
            sub.node(
                pn_id,
                label=build_physical_node_label(pn, nics, node_by_machine, theme),
                shape="plaintext",
            )
            cluster_anchor_ids.append(pn_id)

            detail_nets = []
            compact_nets = []
            for net in child_nets:
                if is_bare_vlan(net, data):
                    compact_nets.append(net)
                else:
                    detail_nets.append(net)

            for net in detail_nets:
                en_id = f"net_{net['$key']}"
                sub.node(en_id, label=build_detail_node(net, data, theme), shape="plaintext")
                dot.edge(pn_id, en_id, color=theme["edge_main"], arrowhead="normal", penwidth="1.2")

            if compact_nets:
                grid_id = f"compact_grid_{pn_key}"
                sub.node(grid_id, label=build_compact_grid(compact_nets, theme, cols=grid_cols), shape="plaintext")
                dot.edge(pn_id, grid_id, color=theme["edge_compact"], arrowhead="normal", penwidth="0.8", style="dashed")

    if overlay_nets:
        detail_overlay = []
        compact_overlay = []
        for net in overlay_nets:
            if is_bare_vlan(net, data):
                compact_overlay.append(net)
            else:
                detail_overlay.append(net)

        overlay_lbl_color = theme.get("overlay_label_color") or theme["text"]
        cluster_idx += 1
        overlay_anchor = None
        with dot.subgraph(name=f"cluster_{cluster_idx}") as sub:
            sub.attr(
                label=f'<{_font(14, overlay_lbl_color, bold=True)}Virtual Overlay Networks{_cfont(True)}>',
                labelloc="t",
                style="rounded,dashed,filled",
                fillcolor=theme["overlay_fill"],
                color=theme["overlay_border"],
                penwidth="1.5",
                margin="16",
            )

            for net in detail_overlay:
                node_id = f"net_{net['$key']}"
                sub.node(node_id, label=build_detail_node(net, data, theme), shape="plaintext")
                if overlay_anchor is None:
                    overlay_anchor = node_id

            if compact_overlay:
                grid_id = "compact_grid_overlay"
                sub.node(grid_id, label=build_compact_grid(compact_overlay, theme, cols=grid_cols), shape="plaintext")
                if overlay_anchor is None:
                    overlay_anchor = grid_id

            if not portrait and len(detail_overlay) > 1:
                with sub.subgraph() as rank_sub:
                    rank_sub.attr(rank="same")
                    for net in detail_overlay:
                        rank_sub.node(f"net_{net['$key']}")

        if overlay_anchor and not portrait:
            cluster_anchor_ids.append(overlay_anchor)

    if phys_without_children:
        cluster_idx += 1
        with dot.subgraph(name=f"cluster_{cluster_idx}") as sub:
            phys_label_color = theme.get("overlay_label_color") or theme["text"]
            sub.attr(
                label=f'<{_font(14, phys_label_color, bold=True)}Other Physical Networks{_cfont(True)}>',
                labelloc="t",
                style="rounded,filled",
                fillcolor=theme["cluster_fill"],
                color=theme["cluster_border"],
                penwidth="1.5",
                margin="16",
            )
            for pn in phys_without_children:
                pn_key = pn["$key"]
                nics = phys_nics.get(pn_key, [])
                pn_id = f"phys_{pn_key}"
                sub.node(
                    pn_id,
                    label=build_physical_node_label(pn, nics, node_by_machine, theme),
                    shape="plaintext",
                )

        other_phys_anchor = f"phys_{phys_without_children[0]['$key']}"
        if cluster_anchor_ids:
            for anchor in cluster_anchor_ids:
                dot.edge(anchor, other_phys_anchor, style="invis", weight="10")
        if portrait:
            with dot.subgraph() as rank_sub:
                rank_sub.attr(rank="sink")
                for pn in phys_without_children:
                    rank_sub.node(f"phys_{pn['$key']}")

    # In portrait mode, place legend to upper right and chain clusters vertically
    if portrait:
        dot.node("legend", label=build_legend(theme), shape="plaintext")
        if cluster_anchor_ids:
            dot.edge(
                cluster_anchor_ids[0],
                "legend",
                style="invis",
            )
            with dot.subgraph() as rank_sub:
                rank_sub.attr(rank="same")
                rank_sub.node(cluster_anchor_ids[0])
                rank_sub.node("legend")
        if len(cluster_anchor_ids) > 1:
            for i in range(len(cluster_anchor_ids) - 1):
                dot.edge(
                    cluster_anchor_ids[i],
                    cluster_anchor_ids[i + 1],
                    style="invis",
                    weight="10",
                )

    # Draw cross-network route edges (only when both endpoints are in the diagram)
    rendered_keys = {n["$key"] for n in networks}
    drawn_edges = set()
    route_colors = theme.get("route_colors", [theme["edge_route"]])
    route_color_idx = 0
    for vnet_key, routes in data["routes_by_vnet"].items():
        if vnet_key not in rendered_keys:
            continue
        for route in routes:
            target = route.get("target_ip", "")
            if target.startswith("vnetkey:"):
                target_key = int(target.split(":")[1])
                if target_key not in rendered_keys:
                    continue
                src_id = f"net_{vnet_key}"
                dst_id = f"net_{target_key}"
                edge_pair = (vnet_key, target_key)
                reverse_pair = (target_key, vnet_key)
                if edge_pair not in drawn_edges and reverse_pair not in drawn_edges:
                    edge_color = route_colors[route_color_idx % len(route_colors)]
                    route_color_idx += 1
                    dot.edge(
                        src_id,
                        dst_id,
                        color=edge_color,
                        style="dashed",
                        arrowhead="open",
                        penwidth="1.0",
                        constraint="false",
                    )
                    drawn_edges.add(edge_pair)

    output_path = dot.render(output_name, cleanup=True)
    print(f"Diagram saved to: {output_path}")
    return output_path


def parse_filter(filter_str):
    """Parse filter string like 'external,internal' or 'has-ip' or 'external+has-ip'."""
    if not filter_str:
        return None, False

    parts = [p.strip().lower() for p in filter_str.split(",")]
    type_filter = []
    has_ip_only = False

    for part in parts:
        if part == "has-ip":
            has_ip_only = True
        elif part in ("external", "internal", "dmz", "core"):
            type_filter.append(part)

    return type_filter or None, has_ip_only


def main():
    parser = argparse.ArgumentParser(
        description="Generate VergeOS network topology diagrams",
        epilog=(
            "Filter examples:\n"
            "  --filter external              Only external networks\n"
            "  --filter external,internal      External and internal\n"
            "  --filter has-ip                 Only networks with an IP assigned\n"
            "  --filter external,has-ip        External networks with an IP\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--url",
        required=True,
        help="VergeOS system URL (e.g., https://192.168.37.10)",
    )
    parser.add_argument("--username", required=True, help="API username")
    parser.add_argument("--password", required=True, help="API password")
    parser.add_argument(
        "--output",
        default="verge_network_diagram",
        help="Output filename without extension (default: verge_network_diagram)",
    )
    parser.add_argument(
        "--format",
        choices=["pdf", "png", "svg"],
        default="png",
        help="Output format (default: png)",
    )
    parser.add_argument("--title", help="Diagram title")
    parser.add_argument(
        "--background",
        choices=["light", "dark"],
        default="light",
        help="Background theme (default: light)",
    )
    parser.add_argument(
        "--layout",
        choices=["landscape", "portrait"],
        default="landscape",
        help="Diagram layout orientation (default: landscape)",
    )
    parser.add_argument(
        "--filter",
        dest="filter_str",
        help="Filter networks: external, internal, dmz, core, has-ip (comma-separated)",
    )
    parser.add_argument(
        "--json-dump",
        action="store_true",
        help="Dump raw API data to JSON file for debugging",
    )

    args = parser.parse_args()

    type_filter, has_ip_only = parse_filter(args.filter_str)

    client = VergeAPIClient(args.url, args.username, args.password)

    try:
        data = collect_data(client, type_filter)
    except requests.exceptions.ConnectionError:
        print(f"Error: Cannot connect to {args.url}", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"Error: API request failed: {e}", file=sys.stderr)
        sys.exit(1)

    if has_ip_only:
        data["networks"] = [
            n for n in data["networks"] if n.get("ipaddress") or n.get("network")
        ]

    net_count = len(data["networks"])
    phys_count = len(data["phys_nets"])
    print(f"Found {net_count} network(s) and {phys_count} physical network(s)")

    if args.json_dump:
        dump = {
            "networks": data["networks"],
            "phys_nets": data["phys_nets"],
            "routes": {str(k): v for k, v in data["routes_by_vnet"].items()},
            "wireguards": {str(k): v for k, v in data["wg_by_vnet"].items()},
        }
        dump_path = f"{args.output}_data.json"
        with open(dump_path, "w") as f:
            json.dump(dump, f, indent=2)
        print(f"Data dumped to: {dump_path}")

    build_diagram(data, args.output, args.format, args.title, args.background, args.layout)


if __name__ == "__main__":
    main()
