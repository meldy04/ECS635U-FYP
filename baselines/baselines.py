"""
Baseline Comparison: EPSS-style and PageRank vs CVSS vs GA

Compares each ranking against the GA Pareto-front ranking using:
  - Spearman rank correlation
  - Top-N overlap (Jaccard)
  - Critical-asset coverage

Output: baseline_rankings.json, baseline_comparison.png
"""

import json
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from scipy.stats import spearmanr
from collections import defaultdict


# ---------------------------------------------------------------------------
# EPSS-style weaponisation weights by CWE
# ---------------------------------------------------------------------------
# Approximated from attacker-utility and known tooling maturity
# (sqlmap, hydra, etc.)
CWE_WEAPONISATION = {
    'CWE-89':  0.95,  # SQL Injection
    'CWE-78':  0.95,  # Command Injection
    'CWE-798': 0.95,  # Hard-coded Credentials
    'CWE-521': 0.90,  # Weak Password Requirements
    'CWE-306': 0.90,  # Missing Authentication
    'CWE-327': 0.70,  # Broken/Risky Crypto
    'CWE-639': 0.70,  # IDOR / Authorisation Bypass
    'CWE-915': 0.65,  # Mass Assignment
    'CWE-862': 0.65,  # Missing Authorization
    'CWE-284': 0.60,  # Improper Access Control
    'CWE-79':  0.55,  # XSS
    'CWE-352': 0.45,  # CSRF
    'CWE-384': 0.55,  # Session Fixation
    'CWE-319': 0.55,  # Cleartext Transmission
    'CWE-312': 0.50,  # Cleartext Storage of Sensitive Info
    'CWE-200': 0.40,  # Information Disclosure
    # Insufficient Logging (enabler only)
    'CWE-778': 0.30,
}

DEFAULT_WEAPONISATION = 0.50

TARGETS = [
    'ASSET_DCS_ADMIN',
    'ASSET_BOARDING_PASS_FORGERY',
    'ASSET_BHS_RCE',
    'ASSET_PII_EXFILTRATION',
    'ASSET_PASSENGER_MANIFEST',
    'ASSET_DCS_DATABASE',
    'ASSET_REDIS_ACCESS',
    'ASSET_FIDS_ADMIN',
]


# ---------------------------------------------------------------------------
# Graph loading and path enumeration
# ---------------------------------------------------------------------------
def load_graph(path='attack_graph.json'):
    with open(path) as f:
        data = json.load(f)
    G = nx.DiGraph()
    for n in data['nodes']:
        G.add_node(n['id'], **{k: v for k, v in n.items() if k != 'id'})
    for e in data['edges']:
        G.add_edge(e['source'], e['target'],
                   **{k: v for k, v in e.items() if k not in ('source', 'target')})
    return data, G


def enumerate_paths(G, source='INITIAL_STATE', cutoff=10):
    paths = []
    for tgt in TARGETS:
        if tgt in G and nx.has_path(G, source, tgt):
            for p in nx.all_simple_paths(G, source, tgt, cutoff=cutoff):
                paths.append((p, tgt, G.nodes[tgt].get('criticality', 0.0)))
    return paths


# ---------------------------------------------------------------------------
# Scoring functions
# ---------------------------------------------------------------------------
def compute_epss_scores(G):
    """epss_score = exploitability * weaponisation(CWE)"""
    scores = {}
    for nid, ndata in G.nodes(data=True):
        if ndata.get('type') != 'vulnerability':
            continue
        in_edges = list(G.in_edges(nid, data=True))
        if in_edges:
            expl = np.mean([e[2].get('exploitability', 0.5) for e in in_edges])
        else:
            expl = 0.5
        cwe = ndata.get('cwe', '')
        weap = CWE_WEAPONISATION.get(cwe, DEFAULT_WEAPONISATION)
        scores[nid] = round(float(expl * weap), 4)
    return scores


def cvss_path_score(G, path):
    """Sum of CVSS scores along the path."""
    s = 0.0
    for nid in path:
        ndata = G.nodes[nid]
        if ndata.get('type') == 'vulnerability':
            s += ndata.get('cvss', 0.0)
    return s


def epss_path_score(G, path, vuln_scores):
    """Joint exploitation probability (product over vulnerabilities)"""
    vulns_on_path = [n for n in path if G.nodes[n].get(
        'type') == 'vulnerability']
    if not vulns_on_path:
        return 0.0
    p = 1.0
    for nid in vulns_on_path:
        p *= vuln_scores.get(nid, DEFAULT_WEAPONISATION)
    return p


def pagerank_path_score(path, pr):
    """Sum of PageRank scores along the path"""
    return sum(pr.get(n, 0.0) for n in path)


def ga_path_fitness(G, path, target_criticality, time_min, time_max,
                    weights=(1.0, 1.0, -1.0, 1.0)):
    """GA Pareto-front fitness replicated for offline ranking"""
    expls, imps, times, sths = [], [], [], []
    for i in range(len(path) - 1):
        e = G[path[i]][path[i + 1]]
        expls.append(e.get('exploitability', 0.5))
        imps.append(e.get('impact', 0.5))
        times.append(e.get('time_estimate', 10.0))
        sths.append(e.get('stealth', 0.5))
    if not expls:
        return 0.0
    exploitability = min(expls)
    impact = (np.prod(imps) ** (1.0 / len(imps))) * target_criticality
    total_time = sum(times)
    norm_time = (total_time - time_min) / max(time_max - time_min, 1e-9)
    stealth = float(np.mean(sths))
    fit = (exploitability, impact, norm_time, stealth)
    return float(sum(w * v for w, v in zip(weights, fit)))


def compute_time_bounds(G, paths):
    times = []
    for p, _, _ in paths:
        t = sum(G[p[i]][p[i+1]].get('time_estimate', 10.0)
                for i in range(len(p) - 1))
        times.append(t)
    if not times:
        return 0.0, 1.0
    return min(times), max(times) if max(times) != min(times) else min(times) + 1.0


# ---------------------------------------------------------------------------
# Comparison helpers
# ---------------------------------------------------------------------------
def rank_vector(order, n):
    v = [0] * n
    for r, idx in enumerate(order):
        v[idx] = r
    return v


def topn_overlap(rank_a, rank_b, n=5):
    a = set(rank_a[:n])
    b = set(rank_b[:n])
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def covered_targets(rows, order, n=5):
    return len({rows[i]['target'] for i in order[:n]})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    data, G = load_graph('../airport-sim/attack_graph.json')
    print(
        f"[+] Graph loaded: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    paths = enumerate_paths(G)
    print(f"[+] Enumerated {len(paths)} candidate attack paths")

    epss_vuln = compute_epss_scores(G)
    print(f"[+] EPSS scores computed for {len(epss_vuln)} vulnerabilities")

    pr = nx.pagerank(G, alpha=0.85)
    print("[+] PageRank computed (alpha=0.85)")

    tmin, tmax = compute_time_bounds(G, paths)

    # Score all paths under each method
    rows = []
    for idx, (p, tgt, crit) in enumerate(paths):
        rows.append({
            'path_index': idx,
            'target': tgt,
            'target_criticality': crit,
            'path_length': len(p),
            'cvss_score': round(cvss_path_score(G, p), 3),
            'epss_score': round(epss_path_score(G, p, epss_vuln), 6),
            'pagerank_score': round(pagerank_path_score(p, pr), 6),
            'ga_fitness': round(ga_path_fitness(G, p, crit, tmin, tmax), 4),
            'path': p,
        })

    # Build rankings (descending)
    def rank_by(key): return [r['path_index'] for r in sorted(
        rows, key=lambda x: x[key], reverse=True)]
    rank_cvss = rank_by('cvss_score')
    rank_epss = rank_by('epss_score')
    rank_pr = rank_by('pagerank_score')
    rank_ga = rank_by('ga_fitness')

    n = len(rows)
    v_ga = rank_vector(rank_ga, n)

    # Spearman correlation vs GA
    spearman_results = {}
    for name, order in [('CVSS', rank_cvss), ('EPSS', rank_epss), ('PageRank', rank_pr)]:
        rho, pval = spearmanr(rank_vector(order, n), v_ga)
        spearman_results[name] = {'rho': round(
            float(rho), 4), 'p': round(float(pval), 6)}

    # Top-N overlap vs GA
    overlap_results = {}
    for name, order in [('CVSS', rank_cvss), ('EPSS', rank_epss), ('PageRank', rank_pr)]:
        overlap_results[name] = {f'top{n_}': round(topn_overlap(order, rank_ga, n_), 3)
                                 for n_ in (3, 5, 10)}

    # Asset coverage
    coverage_results = {
        name: {'top5_targets_covered': covered_targets(rows, order, 5),
               'top10_targets_covered': covered_targets(rows, order, 10)}
        for name, order in [('CVSS', rank_cvss), ('EPSS', rank_epss),
                            ('PageRank', rank_pr), ('GA', rank_ga)]
    }

    # Print summary
    print("\n" + "=" * 70)
    print("COMPARISON SUMMARY")
    print("=" * 70)
    print(f"\nSpearman rank correlation against GA ranking (n={n} paths):")
    for k, v in spearman_results.items():
        print(f"  {k:<10} rho = {v['rho']:+.4f}  (p = {v['p']:.4g})")

    print("\nTop-N Jaccard overlap against GA ranking:")
    print(f"  {'Method':<10} {'Top-3':>8} {'Top-5':>8} {'Top-10':>8}")
    for k, v in overlap_results.items():
        print(
            f"  {k:<10} {v['top3']:>8.2f} {v['top5']:>8.2f} {v['top10']:>8.2f}")

    print("\nDistinct critical-asset targets reached by top-N paths:")
    print(f"  {'Method':<10} {'Top-5':>8} {'Top-10':>8}")
    for k, v in coverage_results.items():
        print(
            f"  {k:<10} {v['top5_targets_covered']:>8} {v['top10_targets_covered']:>8}")

    print("\nTop-5 paths under each ranking method:")
    for name, order in [('CVSS', rank_cvss), ('EPSS', rank_epss),
                        ('PageRank', rank_pr), ('GA', rank_ga)]:
        print(f"\n  -- {name} top-5 --")
        for r, idx in enumerate(order[:5], 1):
            row = rows[idx]
            print(f"    {r}. idx={idx:>3}  target={row['target']:<30} "
                  f"len={row['path_length']}  "
                  f"cvss={row['cvss_score']:>6.2f}  "
                  f"epss={row['epss_score']:.4f}  "
                  f"pr={row['pagerank_score']:.4f}  "
                  f"ga={row['ga_fitness']:+.3f}")

    # Export
    out = {
        'metadata': {
            'n_paths': n,
            'epss_vuln_scores': epss_vuln,
            'pagerank_top10_nodes': dict(sorted(pr.items(), key=lambda x: -x[1])[:10]),
        },
        'rankings': {'cvss': rank_cvss, 'epss': rank_epss, 'pagerank': rank_pr, 'ga': rank_ga},
        'spearman_vs_ga': spearman_results,
        'topn_overlap_vs_ga': overlap_results,
        'target_coverage': coverage_results,
        'path_scores': rows,
    }
    with open('baseline_rankings.json', 'w') as f:
        json.dump(out, f, indent=2)
    print("\n[+] Exported baseline_rankings.json")

    make_plots(rows, rank_ga, rank_cvss, rank_epss, rank_pr, spearman_results)


def make_plots(rows, rank_ga, rank_cvss, rank_epss, rank_pr, spearman):
    n = len(rows)
    v_ga = rank_vector(rank_ga, n)

    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    for ax, (name, rank, color) in zip(
        axes,
        [('CVSS', rank_cvss, '#d95f02'),
         ('EPSS', rank_epss, '#7570b3'),
         ('PageRank', rank_pr, '#1b9e77')]
    ):
        v = rank_vector(rank, n)
        ax.scatter(v_ga, v, alpha=0.6, s=30, color=color,
                   edgecolor='k', linewidth=0.3)
        ax.plot([0, n], [0, n], 'k--', alpha=0.3, linewidth=1)
        ax.set_title(
            f"{name} vs GA ranking\nSpearman rho = {spearman[name]['rho']:+.3f}", fontsize=11)
        ax.set_xlabel('GA rank')
        ax.set_ylabel(f'{name} rank')
        ax.grid(True, alpha=0.3)
        ax.set_xlim(-1, n + 1)
        ax.set_ylim(-1, n + 1)

    plt.suptitle('Ranking-Level Comparison: Baselines vs GA',
                 fontsize=13, fontweight='bold', y=1.02)
    plt.tight_layout()
    plt.savefig('baseline_comparison.png', dpi=200, bbox_inches='tight')
    print("[+] Saved baseline_comparison.png")
    plt.close()


if __name__ == '__main__':
    main()
