"""
Attack Graph Generation using NetworkX
Converts aggregated vulnerability data into directed graph for GA optimization

Input: aggregated_scan_data.json
Output: attack_graph.json, attack_graph.png
"""

import json
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime
from typing import Dict, List, Any, Tuple
import os
from collections import defaultdict


class AttackGraphGenerator:
    """
    Generates attack graph from vulnerability scan data

    Graph Structure:
    - Nodes: Vulnerabilities, Assets, Attack States
    - Edges: Exploit chains with weights (exploitability, impact, time)
    """

    def __init__(self, scan_data_file: str = 'aggregated_scan_data.json'):
        self.graph = nx.DiGraph()
        self.scan_data = self._load_scan_data(scan_data_file)
        self.node_counter = 0
        self.vulnerability_counter = defaultdict(int)

        # Asset criticality mapping
        self.asset_criticality = {
            'fids_web': 0.9,
            'database': 0.8,
            'admin_panel': 0.95,
            'session': 0.7
        }

    def _load_scan_data(self, filename: str) -> Dict[str, Any]:
        """Load aggregated scan data"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            print(f"[+] Loaded scan data from {filename}")
            return data
        except FileNotFoundError:
            print(f"[-] Scan data file not found: {filename}")
            print("[!] Run scan_pipeline.py first to generate data")
            exit(1)

    def add_initial_state(self) -> str:
        """Add initial attacker state"""
        node_id = 'INITIAL_STATE'
        self.graph.add_node(
            node_id,
            type='initial_state',
            label='External Attacker',
            criticality=0.0,
            exploitable=True
        )
        print(f"[+] Added initial state: {node_id}")
        return node_id

    def add_vulnerability_nodes(self) -> List[str]:
        """
        Add vulnerability nodes from scan data
        Returns list of vulnerability node IDs
        """
        vuln_nodes = []

        vuln_by_type = defaultdict(list)
        for vuln in self.scan_data.get('vulnerabilities', []):
            vuln_type = vuln['type']
            vuln_by_type[vuln_type].append(vuln)

        # Create nodes - one per vulnerability type, but include location info
        for vuln_type, vuln_list in vuln_by_type.items():
            # If multiple vulnerabilities of same type, create combined node
            if len(vuln_list) > 1:
                node_id = f"VULN_{vuln_type.replace(' ', '_').replace('(', '').replace(')', '').upper()}"
                locations = [v.get('location', '') for v in vuln_list]

                # Calculate max CVSS
                cvss_values = [v.get('cvss', 0.0) for v in vuln_list]
                max_cvss = max(cvss_values) if cvss_values else 0.0

                # Determine highest severity
                severity_mapping = {
                    'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
                severity_values = [v.get('severity', 'UNKNOWN')
                                   for v in vuln_list]
                highest_severity = max(severity_values,
                                       key=lambda x: severity_mapping.get(x, -1))

                # Check if any are exploitable
                exploitable = any(v.get('exploitable', False)
                                  for v in vuln_list)

                self.graph.add_node(
                    node_id,
                    type='vulnerability',
                    label=f"{vuln_type} ({len(vuln_list)} instances)",
                    cvss=max_cvss,
                    severity=highest_severity,
                    cwe=vuln_list[0].get('cwe', 'N/A'),
                    locations=locations,
                    exploitable=exploitable,
                    count=len(vuln_list)
                )
                vuln_nodes.append(node_id)
                print(
                    f"[+] Added vulnerability: {node_id} - {vuln_type} ({len(vuln_list)} instances)")
            else:
                # Single vulnerability of this type
                vuln = vuln_list[0]
                node_id = f"VULN_{self.node_counter}"
                self.node_counter += 1

                self.graph.add_node(
                    node_id,
                    type='vulnerability',
                    label=vuln_type,
                    cvss=vuln.get('cvss', 0.0),
                    severity=vuln.get('severity', 'UNKNOWN'),
                    cwe=vuln.get('cwe', 'N/A'),
                    location=vuln.get('location', ''),
                    exploitable=vuln.get('exploitable', False),
                    payload=vuln.get('payload', ''),
                    evidence=vuln.get('evidence', '')
                )
                vuln_nodes.append(node_id)
                print(f"[+] Added vulnerability: {node_id} - {vuln_type}")

        return vuln_nodes

    def add_asset_nodes(self) -> Dict[str, str]:
        """
        Add asset nodes
        Returns dict mapping asset names to node IDs
        """
        assets = {
            'web_access': {
                'label': 'Web Application Access',
                'criticality': 0.5,
                'description': 'Public-facing web interface'
            },
            'database': {
                'label': 'Database Access',
                'criticality': 0.8,
                'description': 'Flight/user database'
            },
            'admin_panel': {
                'label': 'Admin Panel Access',
                'criticality': 0.95,
                'description': 'Administrative control'
            },
            'user_credentials': {
                'label': 'User Credentials',
                'criticality': 0.7,
                'description': 'Stored user passwords'
            }
        }

        asset_nodes = {}

        for asset_name, asset_data in assets.items():
            node_id = f"ASSET_{asset_name.upper()}"

            self.graph.add_node(
                node_id,
                type='asset',
                label=asset_data['label'],
                criticality=asset_data['criticality'],
                description=asset_data['description']
            )

            asset_nodes[asset_name] = node_id
            print(f"[+] Added asset: {node_id} - {asset_data['label']}")

        return asset_nodes

    def build_exploit_chains(self, initial_state: str, vuln_nodes: List[str], asset_nodes: Dict[str, str]):
        """
        Build exploit chains (edges) based on vulnerability relationships
        """

        # Map vulnerability types to nodes
        vuln_map = {}
        for node_id in vuln_nodes:
            node_label = self.graph.nodes[node_id]['label']
            if ' (' in node_label:
                base_type = node_label.split(' (')[0]
            else:
                base_type = node_label
            vuln_map[base_type] = node_id

        print("\n[*] Building exploit chains...")

        # 1: Weak Authentication → Direct Admin Access
        weak_auth_types = ['Weak Authentication',
                           'Weak Authentication (multiple instances)']
        for weak_auth_type in weak_auth_types:
            if weak_auth_type in vuln_map:
                self._add_exploit_edge(
                    initial_state,
                    vuln_map[weak_auth_type],
                    exploitability=0.95,
                    impact=0.3,
                    time_estimate=1.0,
                    description="Attempt default credentials"
                )

                self._add_exploit_edge(
                    vuln_map[weak_auth_type],
                    asset_nodes['admin_panel'],
                    exploitability=1.0,
                    impact=0.95,
                    time_estimate=0.5,
                    description="Login with default credentials"
                )
                break

        # 2: SQL Injection → Database → Credentials
        sql_types = ['SQL Injection', 'SQL Injection (multiple instances)']
        for sql_type in sql_types:
            if sql_type in vuln_map:
                self._add_exploit_edge(
                    initial_state,
                    vuln_map[sql_type],
                    exploitability=0.85,
                    impact=0.4,
                    time_estimate=5.0,
                    description="Craft SQL injection payload"
                )

                self._add_exploit_edge(
                    vuln_map[sql_type],
                    asset_nodes['database'],
                    exploitability=0.90,
                    impact=0.8,
                    time_estimate=2.0,
                    description="Extract database contents"
                )

                self._add_exploit_edge(
                    asset_nodes['database'],
                    asset_nodes['user_credentials'],
                    exploitability=1.0,
                    impact=0.7,
                    time_estimate=1.0,
                    description="Extract user password hashes"
                )
                break

        # 3: Credentials → Admin Panel (privilege escalation)
        self._add_exploit_edge(
            asset_nodes['user_credentials'],
            asset_nodes['admin_panel'],
            exploitability=0.80,
            impact=0.95,
            time_estimate=10.0,
            description="Crack weak password hashes"
        )

        # 4: XSS → Session Hijacking → Admin
        xss_types = [
            'Cross-Site Scripting (XSS)', 'XSS', 'Cross-Site Scripting (XSS) (multiple instances)']
        for xss_type in xss_types:
            if xss_type in vuln_map:
                self._add_exploit_edge(
                    initial_state,
                    vuln_map[xss_type],
                    exploitability=0.70,
                    impact=0.3,
                    time_estimate=15.0,
                    description="Inject XSS payload"
                )

                # XSS → Session token theft
                session_node = "ASSET_SESSION_TOKEN"
                if session_node not in self.graph:
                    self.graph.add_node(
                        session_node,
                        type='asset',
                        label='Session Token',
                        criticality=0.7,
                        description='Stolen admin session cookie'
                    )

                self._add_exploit_edge(
                    vuln_map[xss_type],
                    session_node,
                    exploitability=0.85,
                    impact=0.6,
                    time_estimate=2.0,
                    description="Exfiltrate session cookie"
                )

                self._add_exploit_edge(
                    session_node,
                    asset_nodes['admin_panel'],
                    exploitability=1.0,
                    impact=0.95,
                    time_estimate=0.5,
                    description="Use stolen session for admin access"
                )
                break

        # 5: Information Disclosure → Reconnaissance
        info_types = ['Information Disclosure',
                      'Information Disclosure (multiple instances)']
        for info_type in info_types:
            if info_type in vuln_map:
                self._add_exploit_edge(
                    initial_state,
                    vuln_map[info_type],
                    exploitability=0.95,
                    impact=0.2,
                    time_estimate=1.0,
                    description="Access exposed endpoint"
                )

                for sql_type in sql_types:
                    if sql_type in vuln_map:
                        self._add_exploit_edge(
                            vuln_map[info_type],
                            vuln_map[sql_type],
                            exploitability=0.1,
                            impact=0.1,
                            time_estimate=0.5,
                            description="Use disclosed info for better payload"
                        )
                        break
                break

        # 6: Direct path to web access
        self._add_exploit_edge(
            initial_state,
            asset_nodes['web_access'],
            exploitability=1.0,
            impact=0.1,
            time_estimate=0.1,
            description="Access public web interface"
        )

        print(f"[+] Built {self.graph.number_of_edges()} exploit chains")

    def _add_exploit_edge(self, source: str, target: str,
                          exploitability: float, impact: float,
                          time_estimate: float, description: str):
        """
        Add exploit edge with weights for GA fitness function
        """
        weight = (exploitability * impact) / (time_estimate + 1)

        self.graph.add_edge(
            source, target,
            weight=weight,
            exploitability=exploitability,
            impact=impact,
            time_estimate=time_estimate,
            description=description
        )

        print(f"    {source} → {target}")
        print(
            f"      Weight: {weight:.3f} | Exploit: {exploitability} | Impact: {impact} | Time: {time_estimate}min")

    def calculate_path_metrics(self) -> Dict[str, Any]:
        """
        Calculate graph metrics for analysis
        """
        metrics = {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'node_types': {},
            'average_degree': 0,
            'density': nx.density(self.graph),
            'paths_to_admin': 0,
            'shortest_path_length': 0
        }

        # Count node types
        for node in self.graph.nodes(data=True):
            node_type = node[1].get('type', 'unknown')
            metrics['node_types'][node_type] = metrics['node_types'].get(
                node_type, 0) + 1

        # Average degree
        if self.graph.number_of_nodes() > 0:
            degrees = [d for n, d in self.graph.degree()]
            metrics['average_degree'] = sum(degrees) / len(degrees)

        # Count paths to admin panel
        try:
            admin_node = 'ASSET_ADMIN_PANEL'
            initial_node = 'INITIAL_STATE'

            # Check if nodes exist in graph
            if admin_node in self.graph and initial_node in self.graph:
                if nx.has_path(self.graph, initial_node, admin_node):
                    all_paths = list(nx.all_simple_paths(
                        self.graph, initial_node, admin_node))
                    metrics['paths_to_admin'] = len(all_paths)

                    # Get shortest path length (unweighted)
                    try:
                        metrics['shortest_path_length'] = nx.shortest_path_length(
                            self.graph, initial_node, admin_node)
                    except nx.NetworkXNoPath:
                        metrics['shortest_path_length'] = 0
        except Exception as e:
            print(f"[-] Error calculating paths: {e}")

        return metrics

    def identify_critical_paths(self, top_n: int = 3) -> List[Dict[str, Any]]:
        """
        Identify top N critical attack paths to admin panel
        """
        print(f"\n[*] Identifying top {top_n} critical attack paths...")

        initial_node = 'INITIAL_STATE'
        admin_node = 'ASSET_ADMIN_PANEL'

        if not (initial_node in self.graph and admin_node in self.graph):
            print("[-] Required nodes not found in graph")
            return []

        if not nx.has_path(self.graph, initial_node, admin_node):
            print("[-] No path exists from INITIAL to ADMIN_PANEL")
            return []

        # Find all simple paths
        all_paths = list(nx.all_simple_paths(
            self.graph, initial_node, admin_node))

        # Calculate path scores
        path_scores = []
        for path in all_paths:
            total_weight = 0
            total_time = 0
            total_impact = 1.0

            for i in range(len(path) - 1):
                edge_data = self.graph[path[i]][path[i+1]]
                total_weight += edge_data['weight']
                total_time += edge_data['time_estimate']
                total_impact *= edge_data['impact']

            path_scores.append({
                'path': path,
                'total_weight': total_weight,
                'total_time': total_time,
                'total_impact': total_impact,
                'path_length': len(path) - 1
            })

        # Sort by total weight
        path_scores.sort(key=lambda x: x['total_weight'], reverse=True)

        for i, path_info in enumerate(path_scores[:top_n], 1):
            print(f"\n  Path {i} (Weight: {path_info['total_weight']:.3f}):")
            print(f"    Nodes: {len(path_info['path'])}")
            print(f"    Time: {path_info['total_time']:.1f} minutes")
            print(f"    Impact: {path_info['total_impact']:.2f}")
            print(f"    Route: {' → '.join(path_info['path'])}")

        return path_scores[:top_n]

    def visualize_graph(self, output_file: str = 'attack_graph.png'):
        """
        Visualize attack graph using matplotlib
        """
        print("\n[*] Generating graph visualisation...")

        if self.graph.number_of_nodes() == 0:
            print("[-] Graph is empty, skipping visualisation")
            return

        plt.figure(figsize=(16, 12))

        pos = nx.spring_layout(self.graph, k=3, iterations=100)

        initial_nodes = [n for n, d in self.graph.nodes(
            data=True) if d.get('type') == 'initial_state']
        vuln_nodes = [n for n, d in self.graph.nodes(
            data=True) if d.get('type') == 'vulnerability']
        asset_nodes = [n for n, d in self.graph.nodes(
            data=True) if d.get('type') == 'asset']

        nx.draw_networkx_nodes(self.graph, pos, nodelist=initial_nodes,
                               node_color='lightgreen', node_size=2000,
                               label='Initial State', edgecolors='black', linewidths=2)
        nx.draw_networkx_nodes(self.graph, pos, nodelist=vuln_nodes,
                               node_color='orange', node_size=1500,
                               label='Vulnerabilities', edgecolors='black', linewidths=2)
        nx.draw_networkx_nodes(self.graph, pos, nodelist=asset_nodes,
                               node_color='red', node_size=2000,
                               label='Assets/Targets', edgecolors='black', linewidths=2)

        if self.graph.number_of_edges() > 0:
            edge_weights = [self.graph[u][v]['weight']
                            * 3 for u, v in self.graph.edges()]
            nx.draw_networkx_edges(self.graph, pos, width=edge_weights,
                                   alpha=0.7, edge_color='blue', arrows=True,
                                   arrowsize=25, arrowstyle='->', connectionstyle='arc3,rad=0.1')

        labels = {n: self.graph.nodes[n].get(
            'label', n) for n in self.graph.nodes()}
        nx.draw_networkx_labels(self.graph, pos, labels,
                                font_size=9, font_weight='bold')

        if self.graph.number_of_edges() > 0:
            edge_labels = {(u, v): f"{self.graph[u][v]['weight']:.2f}"
                           for u, v in self.graph.edges()}
            nx.draw_networkx_edge_labels(
                self.graph, pos, edge_labels, font_size=8)

        plt.title("FIDS-Web Attack Graph\nNode Color: Green=Initial, Orange=Vuln, Red=Asset",
                  fontsize=16, fontweight='bold', pad=20)
        plt.legend(loc='upper left', fontsize=12)
        plt.axis('off')
        plt.tight_layout()

        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"[+] Graph visualization saved to {output_file}")

    def export_graph(self, output_file: str = 'attack_graph.json'):
        """
        Export graph in JSON format for GA optimization
        """
        graph_data = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'source': 'aggregated_scan_data.json',
                'target': self.scan_data.get('metadata', {}).get('target'),
                'total_nodes': self.graph.number_of_nodes(),
                'total_edges': self.graph.number_of_edges()
            },
            'nodes': [],
            'edges': []
        }

        # Export nodes
        for node_id, node_data in self.graph.nodes(data=True):
            graph_data['nodes'].append({
                'id': node_id,
                **node_data
            })

        # Export edges
        for source, target, edge_data in self.graph.edges(data=True):
            graph_data['edges'].append({
                'source': source,
                'target': target,
                **edge_data
            })

        with open(output_file, 'w') as f:
            json.dump(graph_data, f, indent=2)

        print(f"[+] Attack graph exported to {output_file}")


def main():
    """
    Main execution: Generate attack graph from scan data
    """
    print("="*60)
    print("Attack Graph Generation")
    print("="*60)
    print()

    generator = AttackGraphGenerator('aggregated_scan_data.json')

    # Step 1: Add initial state
    print("[STEP 1] Adding Initial State")
    print("-"*60)
    initial_state = generator.add_initial_state()
    print()

    # Step 2: Add vulnerability nodes
    print("[STEP 2] Adding Vulnerability Nodes")
    print("-"*60)
    vuln_nodes = generator.add_vulnerability_nodes()
    print()

    # Step 3: Add asset nodes
    print("[STEP 3] Adding Asset Nodes")
    print("-"*60)
    asset_nodes = generator.add_asset_nodes()
    print()

    # Step 4: Build exploit chains
    print("[STEP 4] Building Exploit Chains")
    print("-"*60)
    generator.build_exploit_chains(initial_state, vuln_nodes, asset_nodes)
    print()

    # Step 5: Calculate metrics
    print("[STEP 5] Calculating Graph Metrics")
    print("-"*60)
    metrics = generator.calculate_path_metrics()
    print(f"Total Nodes: {metrics['total_nodes']}")
    print(f"Total Edges: {metrics['total_edges']}")
    print(f"Node Types: {metrics['node_types']}")
    print(f"Graph Density: {metrics['density']:.3f}")
    print(f"Paths to Admin: {metrics['paths_to_admin']}")

    # Expected vs actual
    print("\n[+] Expected vs Actual:")
    print("   Expected nodes: ~10 (1 initial + 4-6 vulns + 4-5 assets)")
    print(f"   Actual nodes: {metrics['total_nodes']}")
    print("   Expected edges: ~12")
    print(f"   Actual edges: {metrics['total_edges']}")
    print("   Expected paths to admin: 4")
    print(f"   Actual paths to admin: {metrics['paths_to_admin']}")
    print()

    # Step 6: Identify critical paths
    print("[STEP 6] Identifying Critical Attack Paths")
    print("-"*60)
    critical_paths = generator.identify_critical_paths(top_n=5)
    print()

    # Step 7: Visualise graph
    print("[STEP 7] Generating Visualisation")
    print("-"*60)
    generator.visualize_graph()
    print()

    # Step 8: Export graph
    print("[STEP 8] Exporting Attack Graph")
    print("-"*60)
    generator.export_graph()
    print()

    print("="*60)
    print("Generation Complete!")
    print("="*60)
    print("\nOutput files:")
    print("  - attack_graph.json")
    print("  - attack_graph.png")
    print("="*60)


if __name__ == '__main__':
    main()
