"""
Attack Graph Generation
Converts vulnerability scan data into directed graph for GA optimisation

Input: attack_graph_data.json
Output: attack_graph.json, attack_graph.png
"""

import json
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch
from matplotlib.lines import Line2D
from datetime import datetime
from collections import defaultdict


class AttackGraphGenerator:
    def __init__(self, scan_data_file: str = 'attack_graph_data.json'):
        self.graph = nx.DiGraph()
        self.scan_data = self._load_scan_data(scan_data_file)
        self.node_counter = 0
        self.cross_system_edges = self.scan_data.get('cross_system_edges', [])

    def _load_scan_data(self, filename):
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            print(f"[+] Loaded scan data from {filename}")
            print(f"    Systems: {data['metadata'].get('systems', [])}")
            return data
        except FileNotFoundError:
            print(f"[-] File not found: {filename}")
            exit(1)

    def add_initial_state(self):
        node_id = 'INITIAL_STATE'
        self.graph.add_node(node_id, type='initial_state', label='External Attacker (Kali VM)',
                            criticality=0.0, system='external', exploitable=True)
        print(f"[+] Added initial state: {node_id}")
        return node_id

    def add_vulnerability_nodes(self):
        vuln_nodes = []
        for vuln in self.scan_data.get('vulnerabilities', []):
            node_id = vuln.get('id', f"VULN_{self.node_counter}")
            self.node_counter += 1
            self.graph.add_node(node_id, type='vulnerability',
                                label=f"{vuln['type']} ({vuln['system']})", cvss=vuln.get('cvss', 0.0),
                                cvss_vector=vuln.get('cvss_vector', ''), severity=vuln.get('severity', 'UNKNOWN'),
                                cwe=vuln.get('cwe', 'N/A'), location=vuln.get('location', ''),
                                system=vuln.get('system', 'unknown'), exploitable=vuln.get('exploitable', False),
                                description=vuln.get('description', ''))
            vuln_nodes.append(node_id)
            print(
                f"[+] {node_id} - {vuln['type']} on {vuln['system']} (CVSS: {vuln.get('cvss', 0.0)})")
        return vuln_nodes

    def add_asset_nodes(self):
        asset_nodes = {}
        for asset in self.scan_data.get('assets', []):
            node_id = f"ASSET_{asset['id']}"
            self.graph.add_node(node_id, type='asset', label=asset['name'],
                                criticality=asset.get('criticality', 0.5),
                                description=asset.get('description', ''), system=asset.get('system', 'unknown'))
            asset_nodes[asset['id']] = node_id
            print(
                f"[+] {node_id} - {asset['name']} (crit: {asset['criticality']})")
        pivot_id = "ASSET_NETWORK_PIVOT"
        if pivot_id not in self.graph:
            self.graph.add_node(pivot_id, type='asset', label='Network Pivot Point',
                                criticality=0.9, description='Shell access for lateral movement', system='network')
            asset_nodes['NETWORK_PIVOT'] = pivot_id
        return asset_nodes

    def _add_exploit_edge(self, source, target, exploitability, impact, time_estimate, description, stealth=0.5):
        if source not in self.graph or target not in self.graph or source == target:
            return
        weight = (exploitability * impact) / (time_estimate + 1)
        self.graph.add_edge(source, target, weight=weight, exploitability=exploitability,
                            impact=impact, time_estimate=time_estimate, stealth=stealth, description=description)

    def build_exploit_chains(self, initial_state, vuln_nodes, asset_nodes):
        print("\n[*] Building exploit chains...")
        A = asset_nodes

        # -- DIRECT ACCESS --
        if 'BOOKING_WEB' in A:
            self._add_exploit_edge(
                initial_state, A['BOOKING_WEB'], 1.0, 0.1, 0.1, "Access public booking website", 1.0)
        if 'FIDS_DISPLAY' in A:
            self._add_exploit_edge(
                initial_state, A['FIDS_DISPLAY'], 1.0, 0.05, 0.1, "View public flight display", 1.0)
        if 'DCS_API' in A:
            self._add_exploit_edge(
                initial_state, A['DCS_API'], 0.9, 0.1, 0.2, "Access DCS API (kiosk network)", 0.9)
        if 'BHS_API' in A:
            self._add_exploit_edge(
                initial_state, A['BHS_API'], 0.8, 0.1, 0.5, "Discover BHS on flat network", 0.7)
        self._add_exploit_edge(initial_state, 'VULN_DCS_INFO_DISC',
                               0.95, 0.2, 0.5, "Access /api/system (no auth)", 1.0)
        self._add_exploit_edge(initial_state, 'VULN_FIDS_DEFAULT_CREDS',
                               0.95, 0.3, 1.0, "Try FIDS admin defaults", 0.8)
        self._add_exploit_edge(initial_state, 'VULN_REDIS_NO_AUTH',
                               0.85, 0.3, 1.0, "Discover Redis (port scan)", 0.6)
        self._add_exploit_edge(initial_state, 'VULN_BHS_DEFAULT_CREDS',
                               0.85, 0.4, 1.5, "Discover BHS PostgreSQL 5433", 0.5)

        # -- BOOKING CHAINS --
        self._add_exploit_edge(A.get('BOOKING_WEB', ''), 'VULN_BOOKING_SQLI',
                               0.85, 0.4, 5.0, "Craft SQLi on booking lookup", 0.5)
        self._add_exploit_edge('VULN_BOOKING_SQLI', A.get(
            'BOOKING_DB', ''), 0.9, 0.7, 2.0, "Extract booking DB via SQLi", 0.4)
        self._add_exploit_edge(A.get('BOOKING_WEB', ''), 'VULN_BOOKING_IDOR',
                               0.95, 0.3, 2.0, "Enumerate sequential booking IDs", 0.7)
        self._add_exploit_edge('VULN_BOOKING_IDOR', A.get(
            'BOOKING_DB', ''), 1.0, 0.65, 1.0, "Exfiltrate PII via IDOR", 0.6)
        self._add_exploit_edge(A.get('BOOKING_WEB', ''), 'VULN_BOOKING_INFO_DISC',
                               0.95, 0.15, 0.5, "Trigger DB error messages", 0.9)
        self._add_exploit_edge('VULN_BOOKING_INFO_DISC', 'VULN_BOOKING_SQLI',
                               0.1, 0.1, 0.5, "Schema info aids SQLi", 0.9)

        # -- DCS CHAINS --
        self._add_exploit_edge(A.get('DCS_API', ''), 'VULN_DCS_WEAK_CREDS',
                               0.95, 0.5, 1.0, "Try default creds admin/admin123", 0.7)
        self._add_exploit_edge('VULN_DCS_WEAK_CREDS', A.get(
            'DCS_CHECKIN', ''), 1.0, 0.7, 0.5, "Login as operator", 0.6)
        self._add_exploit_edge('VULN_DCS_WEAK_CREDS', A.get(
            'DCS_ADMIN', ''), 0.9, 0.95, 1.5, "Login as admin", 0.5)
        self._add_exploit_edge('VULN_DCS_INFO_DISC', 'VULN_REDIS_NO_AUTH',
                               0.9, 0.4, 1.0, "Extract Redis host from /api/system", 0.8)
        self._add_exploit_edge(A.get('DCS_API', ''), 'VULN_DCS_JWT',
                               0.85, 0.5, 3.0, "Discover JWT alg:none vuln", 0.4)
        self._add_exploit_edge('VULN_DCS_JWT', A.get(
            'DCS_ADMIN', ''), 0.95, 0.95, 1.0, "Forge admin JWT token", 0.3)
        self._add_exploit_edge('VULN_DCS_JWT', A.get(
            'BOARDING_PASS_FORGERY', ''), 0.95, 1.0, 2.0, "Forge boarding pass JWTs", 0.2)
        self._add_exploit_edge(A.get('DCS_CHECKIN', ''), 'VULN_DCS_MASS_ASSIGN',
                               0.75, 0.4, 2.0, "Craft check-in with extra fields", 0.6)
        self._add_exploit_edge('VULN_DCS_MASS_ASSIGN', A.get(
            'DCS_DATABASE', ''), 0.85, 0.6, 1.0, "Override travel_class/seat", 0.5)
        self._add_exploit_edge(A.get('DCS_CHECKIN', ''), 'VULN_DCS_IDOR',
                               0.95, 0.5, 1.0, "Enumerate booking refs", 0.7)
        self._add_exploit_edge('VULN_DCS_IDOR', A.get(
            'PASSENGER_MANIFEST', ''), 1.0, 0.9, 1.0, "Access manifests via bookings", 0.5)
        self._add_exploit_edge(A.get('DCS_CHECKIN', ''), 'VULN_DCS_SQLI',
                               0.85, 0.4, 5.0, "SQLi on passenger search", 0.4)
        self._add_exploit_edge('VULN_DCS_SQLI', A.get(
            'DCS_DATABASE', ''), 0.9, 0.85, 2.0, "Extract DCS DB via SQLi", 0.3)
        self._add_exploit_edge(A.get('DCS_DATABASE', ''), A.get(
            'PASSENGER_MANIFEST', ''), 1.0, 0.95, 0.5, "Query manifests from DB", 0.5)
        self._add_exploit_edge(A.get('DCS_DATABASE', ''), A.get(
            'PII_EXFILTRATION', ''), 1.0, 1.0, 1.0, "Bulk extract PII (GDPR breach)", 0.2)
        self._add_exploit_edge(A.get('DCS_ADMIN', ''), A.get(
            'DCS_DATABASE', ''), 1.0, 0.95, 0.5, "Admin full DB access", 0.5)
        self._add_exploit_edge(A.get('DCS_ADMIN', ''), A.get(
            'PASSENGER_MANIFEST', ''), 1.0, 0.95, 0.5, "Admin views all manifests", 0.4)
        # Broken RBAC path
        self._add_exploit_edge('VULN_DCS_WEAK_CREDS', 'VULN_DCS_NO_RBAC',
                               0.9, 0.5, 0.5, "Login as kiosk, discover manifest", 0.7)
        self._add_exploit_edge('VULN_DCS_NO_RBAC', A.get(
            'PASSENGER_MANIFEST', ''), 1.0, 0.9, 0.5, "Kiosk views full manifest", 0.6)

        # -- FIDS CHAINS --
        self._add_exploit_edge('VULN_FIDS_DEFAULT_CREDS', A.get(
            'FIDS_ADMIN', ''), 1.0, 0.85, 0.5, "Login FIDS admin/admin", 0.6)
        self._add_exploit_edge(A.get('FIDS_ADMIN', ''), A.get(
            'FIDS_DB', ''), 0.9, 0.6, 1.0, "Access flight cache via admin", 0.5)
        self._add_exploit_edge(A.get(
            'FIDS_ADMIN', ''), 'VULN_FIDS_SQLI', 0.85, 0.4, 3.0, "SQLi via admin search", 0.4)
        self._add_exploit_edge('VULN_FIDS_SQLI', A.get(
            'FIDS_DB', ''), 0.9, 0.6, 2.0, "Extract FIDS cache DB", 0.3)
        self._add_exploit_edge(A.get('FIDS_ADMIN', ''), 'VULN_FIDS_INFO_DISC',
                               1.0, 0.3, 0.5, "View system config in admin", 0.8)
        self._add_exploit_edge(A.get('FIDS_DISPLAY', ''), 'VULN_FIDS_XSS',
                               0.7, 0.3, 10.0, "XSS via manipulated flight status", 0.3)
        self._add_exploit_edge(initial_state, 'VULN_FIDS_NO_SESSION',
                               0.6, 0.3, 2.0, "Discover admin panel URL", 0.5)
        self._add_exploit_edge('VULN_FIDS_NO_SESSION', A.get(
            'FIDS_ADMIN', ''), 0.7, 0.8, 1.0, "Direct URL admin access", 0.4)

        # -- BHS CHAINS --
        self._add_exploit_edge(A.get('BHS_API', ''), 'VULN_BHS_NO_AUTH',
                               1.0, 0.3, 0.5, "Access unauth BHS endpoints", 0.8)
        self._add_exploit_edge('VULN_BHS_NO_AUTH', 'VULN_BHS_CONFIG_EXPOSURE',
                               1.0, 0.5, 0.5, "Query /api/maintenance/config", 0.7)
        self._add_exploit_edge('VULN_BHS_CONFIG_EXPOSURE', A.get(
            'BHS_CONFIG', ''), 1.0, 0.75, 0.5, "Extract API keys, endpoints", 0.6)
        self._add_exploit_edge('VULN_BHS_NO_AUTH', 'VULN_BHS_CMD_INJECTION',
                               0.9, 0.6, 3.0, "Inject cmd in diagnostic", 0.3)
        self._add_exploit_edge('VULN_BHS_CMD_INJECTION', A.get(
            'BHS_RCE', ''), 0.95, 1.0, 2.0, "Achieve RCE on BHS", 0.2)
        self._add_exploit_edge('VULN_BHS_DEFAULT_CREDS', A.get(
            'BHS_DATABASE', ''), 1.0, 0.8, 0.5, "Connect with default creds", 0.4)
        self._add_exploit_edge(A.get('BHS_DATABASE', ''), A.get(
            'PII_EXFILTRATION', ''), 0.9, 0.8, 2.0, "Extract bag-passenger PII", 0.3)

        # -- REDIS CHAINS --
        self._add_exploit_edge('VULN_REDIS_NO_AUTH', A.get(
            'REDIS_ACCESS', ''), 1.0, 0.85, 0.5, "Connect to unauth Redis", 0.5)
        self._add_exploit_edge(A.get('REDIS_ACCESS', ''), A.get(
            'FIDS_DISPLAY', ''), 0.95, 0.9, 1.0, "Publish false flight data", 0.3)
        self._add_exploit_edge(A.get('REDIS_ACCESS', ''), A.get(
            'BHS_API', ''), 0.95, 0.85, 1.0, "Publish false bag routing", 0.3)

        # -- CROSS-SYSTEM LATERAL MOVEMENT --
        self._add_exploit_edge(A.get('BOOKING_DB', ''), A.get(
            'DCS_API', ''), 0.7, 0.6, 5.0, "Booking creds pivot to DCS", 0.4)
        self._add_exploit_edge(A.get('DCS_ADMIN', ''), A.get(
            'FIDS_ADMIN', ''), 0.85, 0.8, 2.0, "DCS admin pivots to FIDS via Redis", 0.4)
        self._add_exploit_edge(A.get('DCS_DATABASE', ''), A.get(
            'BHS_API', ''), 0.8, 0.7, 3.0, "DCS config reveals BHS endpoint", 0.4)
        self._add_exploit_edge('VULN_FIDS_INFO_DISC', A.get(
            'DCS_API', ''), 0.6, 0.5, 5.0, "FIDS admin reveals DCS URL", 0.5)
        self._add_exploit_edge(A.get('BHS_CONFIG', ''), A.get(
            'DCS_API', ''), 0.7, 0.6, 3.0, "BHS config reveals DCS + API key", 0.4)
        self._add_exploit_edge(A.get('BHS_RCE', ''), A.get(
            'NETWORK_PIVOT', ''), 0.9, 0.95, 2.0, "BHS shell enables network scan", 0.2)
        self._add_exploit_edge(A.get('NETWORK_PIVOT', ''), A.get(
            'DCS_DATABASE', ''), 0.7, 0.9, 5.0, "Pivot from BHS to DCS DB", 0.2)

        print(f"\n[+] Built {self.graph.number_of_edges()} exploit chains")

    def calculate_path_metrics(self):
        metrics = {'total_nodes': self.graph.number_of_nodes(), 'total_edges': self.graph.number_of_edges(),
                   'node_types': {}, 'density': nx.density(self.graph)}
        for _, d in self.graph.nodes(data=True):
            t = d.get('type', '?')
            metrics['node_types'][t] = metrics['node_types'].get(t, 0) + 1
        targets = ['ASSET_DCS_ADMIN', 'ASSET_BOARDING_PASS_FORGERY',
                   'ASSET_BHS_RCE', 'ASSET_PII_EXFILTRATION']
        for tgt in targets:
            if tgt in self.graph and 'INITIAL_STATE' in self.graph and nx.has_path(self.graph, 'INITIAL_STATE', tgt):
                metrics[f'paths_to_{tgt}'] = len(
                    list(nx.all_simple_paths(self.graph, 'INITIAL_STATE', tgt, cutoff=10)))
        return metrics

    def identify_critical_paths(self, top_n=5):
        targets = [('ASSET_DCS_ADMIN', 'DCS Admin'), ('ASSET_BOARDING_PASS_FORGERY', 'Boarding Pass Forgery'),
                   ('ASSET_BHS_RCE', 'BHS RCE'), ('ASSET_PII_EXFILTRATION',
                                                  'PII Exfiltration'),
                   ('ASSET_PASSENGER_MANIFEST', 'Passenger Manifest')]
        all_scores = []
        for tid, tname in targets:
            if tid not in self.graph or not nx.has_path(self.graph, 'INITIAL_STATE', tid):
                continue
            for path in nx.all_simple_paths(self.graph, 'INITIAL_STATE', tid, cutoff=10):
                tw, tt, me = 0, 0, 1.0
                for i in range(len(path)-1):
                    e = self.graph[path[i]][path[i+1]]
                    tw += e['weight']
                    tt += e['time_estimate']
                    me = min(me, e['exploitability'])
                all_scores.append({'target': tname, 'path': path, 'total_weight': tw,
                                   'total_time': tt, 'min_exploit': me, 'hops': len(path)-1})
        all_scores.sort(key=lambda x: x['total_weight'], reverse=True)
        for i, p in enumerate(all_scores[:top_n], 1):
            print(
                f"\n  Path {i} -> {p['target']} (W:{p['total_weight']:.3f} T:{p['total_time']:.1f}min)")
            print(f"    {' -> '.join(p['path'])}")
        return all_scores[:top_n]

    def _layered_positions(self, graph, source='INITIAL_STATE'):
        """
        x-coordinates = exploitation depth (BFS distance from initial state)
        y-coordinates = system grouping, keeping related systems clustered verically
        """
        try:
            depths = nx.single_source_shortest_path_length(graph, source)
        except nx.NetworkXError:
            depths = {n: 0 for n in graph.nodes()}

        max_depth = max(depths.values()) if depths else 0
        for n in graph.nodes():
            if n not in depths:
                depths[n] = max_depth + 1

        by_depth = {}
        for n, d in depths.items():
            by_depth.setdefault(d, []).append(n)

        system_order = {
            'external': 0, 'booking': 1, 'dcs': 2, 'fids': 3,
            'bhs': 4, 'redis': 5, 'network': 6, 'unknown': 7
        }

        pos = {}
        for d, nodes in by_depth.items():
            nodes_sorted = sorted(
                nodes,
                key=lambda n: (system_order.get(
                    graph.nodes[n].get('system', 'unknown'), 99), n)
            )
            n_count = len(nodes_sorted)
            # Spread vertically across [-1, 1] leaving margin
            if n_count == 1:
                ys = [0.0]
            else:
                ys = list(np.linspace(1.0, -1.0, n_count))
            for n, y in zip(nodes_sorted, ys):
                pos[n] = (d * 1.6, y)
        return pos

    def _short_label(self, graph, node):
        """Trim longer node labels for display"""
        label = graph.nodes[node].get('label', node)
        if '(' in label and graph.nodes[node].get('type') == 'vulnerability':
            label = label.split('(')[0].strip()
        if len(label) > 24:
            label = label[:22] + '..'
        return label

    def visualise_graph(self, output_file='attack_graph.png'):
        """
        Hierarchical attack graph visualisation.
        - x-axis = attack depth
        - Node shape = node type (diamond=initial, circle=vulnerability, square=asset)
        - Node colour = system
        """
        if not self.graph.number_of_nodes():
            return

        fig, ax = plt.subplots(figsize=(20, 12))
        pos = self._layered_positions(self.graph)

        system_colors = {
            'external': '#27ae60', 'booking': '#3498db', 'dcs': '#e74c3c',
            'fids': '#f39c12', 'bhs': '#9b59b6', 'redis': '#16a085',
            'network': '#7f8c8d', 'unknown': '#bdc3c7'
        }

        # Edges
        edge_alpha = 0.35
        nx.draw_networkx_edges(
            self.graph, pos, ax=ax,
            edge_color='#2c3e50', width=0.9, alpha=edge_alpha,
            arrows=True, arrowsize=10, arrowstyle='-|>',
            connectionstyle='arc3,rad=0.08',
            node_size=900,
        )

        # Nodes by type and system
        type_shape = {'initial_state': 'D', 'asset': 's', 'vulnerability': 'o'}
        type_size = {'initial_state': 1100, 'asset': 950, 'vulnerability': 600}

        for ntype, shape in type_shape.items():
            for syst, color in system_colors.items():
                nodes = [
                    n for n, d in self.graph.nodes(data=True)
                    if d.get('type') == ntype and d.get('system') == syst
                ]
                if not nodes:
                    continue
                nx.draw_networkx_nodes(
                    self.graph, pos, ax=ax, nodelist=nodes,
                    node_shape=shape, node_color=color,
                    node_size=type_size[ntype],
                    edgecolors='black', linewidths=1.2,
                )

        # Labels below nodes
        label_pos = {n: (x, y - 0.09) for n, (x, y) in pos.items()}
        labels = {n: self._short_label(self.graph, n)
                  for n in self.graph.nodes()}
        nx.draw_networkx_labels(
            self.graph, label_pos, labels=labels, ax=ax,
            font_size=6.5, font_weight='normal',
        )

        # Two-dimensional legend
        type_legend = [
            Line2D([0], [0], marker='D', color='w', markerfacecolor='#7f8c8d',
                   markersize=11, markeredgecolor='black', label='Initial State'),
            Line2D([0], [0], marker='o', color='w', markerfacecolor='#7f8c8d',
                   markersize=10, markeredgecolor='black', label='Vulnerability'),
            Line2D([0], [0], marker='s', color='w', markerfacecolor='#7f8c8d',
                   markersize=11, markeredgecolor='black', label='Asset'),
        ]
        color_legend = [
            Patch(facecolor=system_colors['booking'],
                  edgecolor='black', label='Booking'),
            Patch(facecolor=system_colors['dcs'],
                  edgecolor='black', label='DCS (hub)'),
            Patch(facecolor=system_colors['fids'],
                  edgecolor='black', label='FIDS'),
            Patch(facecolor=system_colors['bhs'],
                  edgecolor='black', label='BHS'),
            Patch(facecolor=system_colors['redis'],
                  edgecolor='black', label='Redis'),
            Patch(facecolor=system_colors['network'],
                  edgecolor='black', label='Network'),
        ]

        leg1 = ax.legend(handles=type_legend, loc='upper left',
                         title='Node Type', fontsize=9, title_fontsize=10,
                         framealpha=0.95)
        ax.add_artist(leg1)
        ax.legend(handles=color_legend, loc='lower left',
                  title='System', fontsize=9, title_fontsize=10, framealpha=0.95)

        # Depth annotation
        depths = nx.single_source_shortest_path_length(
            self.graph, 'INITIAL_STATE')
        max_d = max(depths.values())
        ax.annotate(
            '', xy=(max_d * 1.6 + 0.5, -1.35), xytext=(-0.5, -1.35),
            arrowprops=dict(arrowstyle='->', color='#34495e', lw=1.2)
        )
        ax.text((max_d * 1.6) / 2, -1.45, 'Attack progression (exploitation depth)',
                ha='center', fontsize=10, style='italic', color='#34495e')

        ax.set_title(
            'Attack Graph — Airport IT Simulation\n'
            'Hub-and-spoke topology (DCS Central)',
            fontsize=14, fontweight='bold', pad=15
        )
        ax.set_xlim(-1.0, max_d * 1.6 + 1.0)
        ax.set_ylim(-1.6, 1.3)
        ax.axis('off')
        plt.tight_layout()
        plt.savefig(output_file, dpi=300,
                    bbox_inches='tight', facecolor='white')
        plt.close()
        print(f"[+] Saved {output_file}")

    def visualise_ga_path(self, path, output_file='attack_graph_ga_path.png',
                          path_label='GA Top-Ranked Attack Path'):
        """
        Render the same hierarchical layout with a single attack path highlighted.
        Non-path elements are faded to background.
        """
        if not self.graph.number_of_nodes() or not path:
            return

        fig, ax = plt.subplots(figsize=(20, 12))
        pos = self._layered_positions(self.graph)

        system_colors = {
            'external': '#27ae60', 'booking': '#3498db', 'dcs': '#e74c3c',
            'fids': '#f39c12', 'bhs': '#9b59b6', 'redis': '#16a085',
            'network': '#7f8c8d', 'unknown': '#bdc3c7'
        }

        path_set = set(path)
        path_edges = set(zip(path[:-1], path[1:]))

        # Background edges faded
        bg_edges = [(u, v)
                    for u, v in self.graph.edges() if (u, v) not in path_edges]
        nx.draw_networkx_edges(
            self.graph, pos, ax=ax, edgelist=bg_edges,
            edge_color='#bdc3c7', width=0.6, alpha=0.25,
            arrows=True, arrowsize=7, arrowstyle='-|>',
            connectionstyle='arc3,rad=0.08', node_size=900,
        )

        type_shape = {'initial_state': 'D', 'asset': 's', 'vulnerability': 'o'}
        type_size = {'initial_state': 1100, 'asset': 950, 'vulnerability': 600}

        # Background nodes faded
        for ntype, shape in type_shape.items():
            for syst, color in system_colors.items():
                nodes = [
                    n for n, d in self.graph.nodes(data=True)
                    if d.get('type') == ntype and d.get('system') == syst
                    and n not in path_set
                ]
                if not nodes:
                    continue
                nx.draw_networkx_nodes(
                    self.graph, pos, ax=ax, nodelist=nodes,
                    node_shape=shape, node_color=color,
                    node_size=type_size[ntype],
                    edgecolors='gray', linewidths=0.6, alpha=0.25,
                )

        # Path edges highlighted
        nx.draw_networkx_edges(
            self.graph, pos, ax=ax, edgelist=list(path_edges),
            edge_color='#c0392b', width=3.2, alpha=0.95,
            arrows=True, arrowsize=22, arrowstyle='-|>',
            connectionstyle='arc3,rad=0.08', node_size=900,
        )

        # Path nodes highlighted
        for ntype, shape in type_shape.items():
            for syst, color in system_colors.items():
                nodes = [
                    n for n, d in self.graph.nodes(data=True)
                    if d.get('type') == ntype and d.get('system') == syst
                    and n in path_set
                ]
                if not nodes:
                    continue
                nx.draw_networkx_nodes(
                    self.graph, pos, ax=ax, nodelist=nodes,
                    node_shape=shape, node_color=color,
                    node_size=type_size[ntype] * 1.25,
                    edgecolors='#c0392b', linewidths=2.2,
                )

        # Labels: full for path nodes, fade the rest
        label_pos = {n: (x, y - 0.09) for n, (x, y) in pos.items()}
        path_labels = {n: self._short_label(self.graph, n) for n in path_set}
        bg_labels = {
            n: self._short_label(self.graph, n)
            for n in self.graph.nodes() if n not in path_set
        }
        nx.draw_networkx_labels(
            self.graph, label_pos, labels=bg_labels, ax=ax,
            font_size=5.5, font_weight='normal', alpha=0.4,
        )
        nx.draw_networkx_labels(
            self.graph, label_pos, labels=path_labels, ax=ax,
            font_size=8, font_weight='bold',
        )

        # Step numbers on path
        for i, n in enumerate(path):
            x, y = pos[n]
            ax.text(x + 0.18, y + 0.14, str(i), ha='center', va='center',
                    fontsize=9, fontweight='bold', color='white',
                    bbox=dict(boxstyle='circle,pad=0.18',
                              fc='#c0392b', ec='black', lw=1),
                    zorder=10)

        # Legend
        type_legend = [
            Line2D([0], [0], marker='D', color='w', markerfacecolor='#7f8c8d',
                   markersize=11, markeredgecolor='black', label='Initial State'),
            Line2D([0], [0], marker='o', color='w', markerfacecolor='#7f8c8d',
                   markersize=10, markeredgecolor='black', label='Vulnerability'),
            Line2D([0], [0], marker='s', color='w', markerfacecolor='#7f8c8d',
                   markersize=11, markeredgecolor='black', label='Asset'),
            Line2D([0], [0], color='#c0392b', lw=3.2, label='GA-ranked path'),
        ]
        color_legend = [
            Patch(facecolor=system_colors['booking'],
                  edgecolor='black', label='Booking'),
            Patch(facecolor=system_colors['dcs'],
                  edgecolor='black', label='DCS (hub)'),
            Patch(facecolor=system_colors['fids'],
                  edgecolor='black', label='FIDS'),
            Patch(facecolor=system_colors['bhs'],
                  edgecolor='black', label='BHS'),
            Patch(facecolor=system_colors['redis'],
                  edgecolor='black', label='Redis'),
            Patch(facecolor=system_colors['network'],
                  edgecolor='black', label='Network'),
        ]
        leg1 = ax.legend(handles=type_legend, loc='upper left',
                         title='Node Type', fontsize=9, title_fontsize=10, framealpha=0.95)
        ax.add_artist(leg1)
        ax.legend(handles=color_legend, loc='lower right',
                  title='System', fontsize=9, title_fontsize=10, framealpha=0.95, ncol=2)

        depths = nx.single_source_shortest_path_length(
            self.graph, 'INITIAL_STATE')
        max_d = max(depths.values())
        ax.annotate(
            '', xy=(max_d * 1.6 + 0.5, -1.35), xytext=(-0.5, -1.35),
            arrowprops=dict(arrowstyle='->', color='#34495e', lw=1.2)
        )
        ax.text((max_d * 1.6) / 2 - 2.0, -1.45, 'Attack progression (exploitation depth)',
                ha='center', fontsize=10, style='italic', color='#34495e')

        ax.set_title(
            f'{path_label}\n'
            f'Numbered steps trace exploitation order ({len(path)-1} hops, '
            f'{len(path)} nodes)',
            fontsize=14, fontweight='bold', pad=15
        )
        ax.set_xlim(-1.0, max_d * 1.6 + 1.0)
        ax.set_ylim(-1.6, 1.3)
        ax.axis('off')
        plt.tight_layout()
        plt.savefig(output_file, dpi=300,
                    bbox_inches='tight', facecolor='white')
        plt.close()
        print(f"[+] Saved {output_file}")

    def export_graph(self, output_file='attack_graph.json'):
        data = {'metadata': {'timestamp': datetime.now().isoformat(), 'total_nodes': self.graph.number_of_nodes(), 'total_edges': self.graph.number_of_edges()},
                'nodes': [{'id': n, **d} for n, d in self.graph.nodes(data=True)],
                'edges': [{'source': s, 'target': t, **d} for s, t, d in self.graph.edges(data=True)]}
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[+] Exported {output_file}")


def main():
    print("="*60)
    print("Attack Graph Generation")
    print("="*60+"\n")
    g = AttackGraphGenerator('attack_graph_data.json')
    init = g.add_initial_state()
    vulns = g.add_vulnerability_nodes()
    assets = g.add_asset_nodes()
    g.build_exploit_chains(init, vulns, assets)
    m = g.calculate_path_metrics()
    print(
        f"\n  Nodes: {m['total_nodes']} | Edges: {m['total_edges']} | Density: {m['density']:.3f}")
    critical_paths = g.identify_critical_paths()
    g.visualise_graph('attack_graph.png')

    if critical_paths and len(critical_paths) > 0:
        top_path = critical_paths[0]['path']
        g.visualise_ga_path(top_path, 'attack_graph_ga_path.png',
                            'Top-Ranked Attack Path')

    g.export_graph()
    print("\n"+"="*60+"\nComplete!\n"+"="*60)


if __name__ == '__main__':
    main()
