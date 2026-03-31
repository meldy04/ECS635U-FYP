"""
Attack Graph Generation
Converts vulnerability scan data into directed graph for GA optimisation

Input: attack_graph_data.json
Output: attack_graph.json, attack_graph.png
"""

import json
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime
from typing import Dict, List, Any
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

    def visualise_graph(self, output_file='attack_graph.png'):
        if not self.graph.number_of_nodes():
            return
        plt.figure(figsize=(20, 14))
        pos = nx.spring_layout(self.graph, k=2.5, iterations=100, seed=42)
        colors = {'external': '#2ecc71', 'booking': '#3498db', 'dcs': '#e74c3c',
                  'fids': '#f39c12', 'bhs': '#9b59b6', 'redis': '#1abc9c', 'network': '#95a5a6'}
        for s, c in colors.items():
            nodes = [n for n, d in self.graph.nodes(
                data=True) if d.get('system') == s]
            if nodes:
                sizes = [2500 if self.graph.nodes[n].get('type') == 'initial_state' else 2000 if self.graph.nodes[n].get(
                    'type') == 'asset' else 1200 for n in nodes]
                nx.draw_networkx_nodes(self.graph, pos, nodelist=nodes, node_color=c,
                                       node_size=sizes, label=s.upper(), edgecolors='black', linewidths=1.5)
        ew = [self.graph[u][v]['weight']*2.5 for u, v in self.graph.edges()]
        nx.draw_networkx_edges(self.graph, pos, width=ew, alpha=0.6, edge_color='#555',
                               arrows=True, arrowsize=20, connectionstyle='arc3,rad=0.1')
        labels = {n: (self.graph.nodes[n].get('label', n)[:22]+'...' if len(self.graph.nodes[n].get(
            'label', n)) > 25 else self.graph.nodes[n].get('label', n)) for n in self.graph.nodes()}
        nx.draw_networkx_labels(self.graph, pos, labels,
                                font_size=7, font_weight='bold')
        plt.title("Airport IT Simulation - Attack Graph\nHub-and-Spoke (DCS Central)",
                  fontsize=16, fontweight='bold')
        plt.legend(loc='upper left', fontsize=7, labelspacing=1.2,
                   framealpha=0.9, markerscale=0.6)
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
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
    g.identify_critical_paths()
    g.visualise_graph()
    g.export_graph()
    print("\n"+"="*60+"\nComplete!\n"+"="*60)


if __name__ == '__main__':
    main()
