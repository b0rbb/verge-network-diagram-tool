VergeOS Network Diagram Tool

Generates 2D network topology diagrams from a VergeOS system via the API. Shows External, Internal, DMZ, and Core networks grouped by their backing Physical Networks, with Node NIC connections, services, and routing tables. The diagram is titled with the system's cluster name and System ID, and External networks show their live public (egress) IP. Exports to PNG, PDF, or SVG.

Prerequisites

- Python 3.10+
- Graphviz system package (the `dot` binary must be in your PATH)
  - macOS: `brew install graphviz`
  - Ubuntu/Debian: `apt install graphviz`
  - Windows: graphviz.org/download
- A VergeOS user account with API read access

Setup

```bash
git clone <repo-url> && cd verge-network-diagram-tool
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Basic Usage

```bash
python verge_network_diagram.py \
  --url https://YOUR-VERGE-HOST \
  --username YOUR_USER \
  --password YOUR_PASS
```

This generates `verge_network_diagram.png` in the current directory.

Options

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | (required) | VergeOS system URL |
| `--username` | (required) | API username |
| `--password` | (required) | API password |
| `--output` | `verge_network_diagram` | Output filename (without extension) |
| `--format` | `png` | Output format: `png`, `pdf`, or `svg` |
| `--title` | Auto (cluster name) | Diagram title text |
| `--background` | `light` | Theme: `light` (white) or `dark` (dark navy) |
| `--layout` | `landscape` | Layout orientation: `landscape` or `portrait` |
| `--filter` | (all networks) | Filter networks (see below) |
| `--json-dump` | off | Also save raw API data to a JSON file |

Filter Examples

```bash
# Only external networks
--filter external

# External and internal networks
--filter external,internal

# Only networks that have an IP address assigned
--filter has-ip

# External networks with an IP (combine filters with commas)
--filter external,has-ip
```

Filter values: `external`, `internal`, `dmz`, `core`, `has-ip`

Full Examples

```bash
# PDF export with dark background, external networks only
python verge_network_diagram.py \
  --url https://192.168.1.100 \
  --username admin \
  --password MyPass \
  --format pdf \
  --background dark \
  --filter external \
  --title "Production External Networks"

# Portrait layout SVG with all networks and a JSON data dump
python verge_network_diagram.py \
  --url https://10.0.0.5 \
  --username api-user \
  --password Secret123 \
  --format svg \
  --layout portrait \
  --json-dump \
  --output my_site_diagram

# Quick overview: only networks with IPs configured
python verge_network_diagram.py \
  --url https://verge.example.com \
  --username readonly \
  --password ViewOnly1 \
  --filter has-ip
```

What the Diagram Shows

- **Physical Networks** (blue headers) -- the backing virtual switches with their Node NIC connections, driver info, and bond status
- **External Networks** (green) -- VLAN ID, IP address, subnet, gateway, IP type, live public/egress IP
- **Internal Networks** (purple) -- tenant and overlay networks
- **DMZ Networks** (brown) -- inter-vnet communication networks
- **Core Networks** (steel blue) -- vSAN and node traffic networks
- **Services** (yellow row) -- WireGuard, DHCP, DNS, BGP, IPSec when enabled
- **Routes** (blue row) -- routing table entries with targets
- **Trunk-only VLANs** -- bare VLANs with no IP are shown as a compact grid
- **Colored dashed lines** -- inter-network route relationships (each route gets a distinct color)
- **Other Physical Networks** -- physical networks with no child external networks are grouped together at the bottom
- **Title** -- auto-defaults to the cluster (cloud) name with System ID subtitle

Notes

- Self-signed TLS certificates are accepted automatically
- The API user only needs read permissions
- The `whatsmyip` diagnostic is run on each external network to detect the live public IP (adds a few seconds per external network)
- Large environments with many VLANs will benefit from `--filter has-ip` for a cleaner diagram
- Portrait layout places the legend in the upper right corner
