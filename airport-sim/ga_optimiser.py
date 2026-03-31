"""
Genetic Algorithm Attack Path Optimiser

Uses DEAP NSGA-II to optimise attack path selection.
Multi-target: DCS Admin, Boarding Pass Forgery, BHS RCE, PII Exfiltration

Input: attack_graph.json
Output: optimised_attack_paths.json, ga_evolution.png
"""

from deap import creator, base, tools, algorithms
import json
import random
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime
from typing import List, Dict, Any, Tuple
import time


class AttackPathOptimiser:
    """GA optimiser for multi-target attack path prioritisation"""

    # High-value targets in order of criticality
    TARGETS = [
        'ASSET_DCS_ADMIN',
        'ASSET_BOARDING_PASS_FORGERY',
        'ASSET_BHS_RCE',
        'ASSET_PII_EXFILTRATION',
        'ASSET_PASSENGER_MANIFEST',
        'ASSET_DCS_DATABASE',
        'ASSET_REDIS_ACCESS',
        'ASSET_FIDS_ADMIN'
    ]

    def __init__(self, graph_file: str = 'attack_graph.json'):
        self.graph_data = self._load_graph(graph_file)
        self.graph = self._build_networkx_graph()
        self.source_node = self._find_source_node()
        self.target_nodes = self._find_target_nodes()

        # Find all valid paths to all targets
        self.all_paths = self._enumerate_all_paths()

        self._configure_ga_parameters()
        self._setup_deap()

        self.evolution_stats = {
            'generations': [], 'best_fitness': [],
            'avg_fitness': [], 'diversity': []
        }

    def _load_graph(self, filename):
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            print(
                f"[+] Loaded attack graph: {data['metadata']['total_nodes']} nodes, {data['metadata']['total_edges']} edges")
            return data
        except FileNotFoundError:
            print(
                f"[-] File not found: {filename}. Run attack_graph_generator.py first.")
            exit(1)

    def _build_networkx_graph(self):
        G = nx.DiGraph()
        for node in self.graph_data['nodes']:
            G.add_node(node['id'], **{k: v for k,
                       v in node.items() if k != 'id'})
        for edge in self.graph_data['edges']:
            G.add_edge(edge['source'], edge['target'],
                       **{k: v for k, v in edge.items() if k not in ['source', 'target']})
        return G

    def _find_source_node(self):
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'initial_state':
                print(f"[+] Source: {node}")
                return node
        print("[-] No source node found.")
        return None

    def _find_target_nodes(self):
        """Find all reachable high-value targets"""
        targets = []
        for target_id in self.TARGETS:
            if target_id in self.graph and self.source_node:
                if nx.has_path(self.graph, self.source_node, target_id):
                    crit = self.graph.nodes[target_id].get('criticality', 0)
                    targets.append((target_id, crit))
                    print(f"[+] Target: {target_id} (criticality: {crit})")

        if not targets:
            # Fallback find highest criticality reachable asset
            for node, data in self.graph.nodes(data=True):
                if data.get('type') == 'asset' and nx.has_path(self.graph, self.source_node, node):
                    targets.append((node, data.get('criticality', 0)))

            targets.sort(key=lambda x: x[1], reverse=True)
            targets = targets[:5]
            print(f"[+] Fallback targets: {[t[0] for t in targets]}")

        return targets

    def _enumerate_all_paths(self):
        """Find all simple paths from source to all targets"""
        all_paths = []
        if not self.source_node or not self.target_nodes:
            return []

        for target_id, criticality in self.target_nodes:
            try:
                paths = list(nx.all_simple_paths(
                    self.graph, self.source_node, target_id, cutoff=10))
                for path in paths:
                    all_paths.append((path, target_id, criticality))
            except nx.NetworkXError:
                continue

        print(
            f"[+] Found {len(all_paths)} valid attack paths across {len(self.target_nodes)} targets")

        # Show sample paths
        for i, (path, target, crit) in enumerate(all_paths[:5], 1):
            summary = ' -> '.join(path[:3])
            if len(path) > 3:
                summary += f" -> ... ({len(path)-3} more)"
            print(f"    {i}. [{crit:.1f}] {summary} -> {target}")

        return all_paths

    def _configure_ga_parameters(self):
        path_count = len(self.all_paths)

        if path_count > 500:
            self.population_size = 150
            self.generations = 150
        elif path_count > 100:
            self.population_size = 100
            self.generations = 100
        elif path_count > 30:
            self.population_size = 80
            self.generations = 80
        else:
            self.population_size = 50
            self.generations = 50

        self.crossover_prob = 0.7
        self.mutation_prob = 0.2

        print(f"[+] GA Parameters: pop={self.population_size}, gen={self.generations}, "
              f"cx={self.crossover_prob}, mut={self.mutation_prob}")

    def _setup_deap(self):
        """Configure DEAP for multi-objective optimisation NSGA-II)="""
        # Fitness: maximise exploitability, impact, stealth; minimise time
        if not hasattr(creator, "FitnessMulti"):
            creator.create("FitnessMulti", base.Fitness,
                           weights=(1.0, 1.0, -1.0, 1.0))

        if not hasattr(creator, "Individual"):
            creator.create("Individual", list, fitness=creator.FitnessMulti)

        self.toolbox = base.Toolbox()

        max_index = max(0, len(self.all_paths) - 1)
        self.toolbox.register("attr_path", random.randint, 0, max_index)
        self.toolbox.register("individual", tools.initRepeat, creator.Individual,
                              self.toolbox.attr_path, n=1)
        self.toolbox.register("population", tools.initRepeat,
                              list, self.toolbox.individual)
        self.toolbox.register("evaluate", self._fitness_function)
        self.toolbox.register("mate", self._crossover)
        self.toolbox.register("mutate", self._mutate)
        self.toolbox.register("select", tools.selNSGA2)

        print("[+] DEAP configured NSGA-II")

    def _fitness_function(self, individual):
        """
        Multi-objective fitness:
        Returns: (exploitability, impact, time, stealth)

        Impact incorporates target criticality, hence paths 
        to higher-value targets (DCS Admin, Boarding Pass Forgery)
        score higher than paths to lower-value targets.
        """
        path_index = individual[0]

        if not self.all_paths or path_index >= len(self.all_paths):
            return (0.0, 0.0, 1000.0, 0.0)

        path, target_id, target_criticality = self.all_paths[path_index]

        exploitability_scores = []
        impact_scores = []
        time_estimates = []
        stealth_scores = []

        for i in range(len(path) - 1):
            try:
                edge = self.graph[path[i]][path[i + 1]]
                exploitability_scores.append(edge.get('exploitability', 0.5))
                impact_scores.append(edge.get('impact', 0.5))
                time_estimates.append(edge.get('time_estimate', 10.0))
                stealth_scores.append(edge.get('stealth', 0.5))
            except (KeyError, IndexError):
                exploitability_scores.append(0.3)
                impact_scores.append(0.3)
                time_estimates.append(15.0)
                stealth_scores.append(0.3)

        # Exploitability: minimum along path (chain is as strong as weakest link)
        exploitability = min(
            exploitability_scores) if exploitability_scores else 0.0

        # Impact: product of edge impacts * target criticality
        impact = np.prod(impact_scores) * \
            target_criticality if impact_scores else 0.0

        # Time: sum of all steps
        total_time = sum(time_estimates)

        # Stealth: average stealth weighted by inverse path length
        avg_stealth = np.mean(stealth_scores) if stealth_scores else 0.0
        stealth = avg_stealth * (1.0 / len(path)) if len(path) > 1 else 0.0

        return (exploitability, impact, total_time, stealth)

    def _crossover(self, ind1, ind2):
        if random.random() < 0.5:
            ind1[0], ind2[0] = ind2[0], ind1[0]
        return ind1, ind2

    def _mutate(self, individual):
        max_index = max(0, len(self.all_paths) - 1)
        individual[0] = random.randint(0, max_index)
        return (individual,)

    def run_optimisation(self):
        """Run GA optimisation with NSGA-II."""
        if not self.all_paths:
            print("[-] No attack paths to optimise")
            return []

        print("\n" + "=" * 60)
        print("Running GA Optimisation NSGA-II")
        print("=" * 60 + "\n")

        population = self.toolbox.population(n=self.population_size)
        fitnesses = list(map(self.toolbox.evaluate, population))
        for ind, fit in zip(population, fitnesses):
            ind.fitness.values = fit

        start_time = time.time()

        for gen in range(1, self.generations + 1):
            offspring = self.toolbox.select(population, len(population))
            offspring = list(map(self.toolbox.clone, offspring))

            for child1, child2 in zip(offspring[::2], offspring[1::2]):
                if random.random() < self.crossover_prob:
                    self.toolbox.mate(child1, child2)
                    del child1.fitness.values
                    del child2.fitness.values

            for mutant in offspring:
                if random.random() < self.mutation_prob:
                    self.toolbox.mutate(mutant)
                    del mutant.fitness.values

            invalid_ind = [ind for ind in offspring if not ind.fitness.valid]
            if invalid_ind:
                fitnesses = map(self.toolbox.evaluate, invalid_ind)
                for ind, fit in zip(invalid_ind, fitnesses):
                    ind.fitness.values = fit

            population[:] = offspring

            fits = [ind.fitness.values for ind in population if ind.fitness.valid]
            if fits:
                best_fit = max(fits, key=lambda x: sum(x))
                avg_fit = [sum(f[i] for f in fits) / len(fits)
                           for i in range(4)]
                diversity = len(
                    set(ind[0] for ind in population)) / max(1, len(self.all_paths))

                self.evolution_stats['generations'].append(gen)
                self.evolution_stats['best_fitness'].append(sum(best_fit))
                self.evolution_stats['avg_fitness'].append(sum(avg_fit))
                self.evolution_stats['diversity'].append(diversity)

                if gen % 10 == 0 or gen == 1:
                    print(f"  Gen {gen}/{self.generations} | Best: {sum(best_fit):.3f} | "
                          f"Avg: {sum(avg_fit):.3f} | Diversity: {diversity:.1%}")

        elapsed = time.time() - start_time
        print(f"\n[+] Complete in {elapsed:.2f}s")

        # Extract Pareto front
        valid_pop = [ind for ind in population if ind.fitness.valid]
        if valid_pop:
            pareto_front = tools.sortNondominated(
                valid_pop, len(valid_pop), first_front_only=True)[0]
        else:
            pareto_front = []

        # Convert to results
        optimised_paths = []
        seen_paths = set()
        for ind in pareto_front:
            idx = ind[0]
            if idx >= len(self.all_paths) or idx in seen_paths:
                continue
            seen_paths.add(idx)

            path, target_id, target_crit = self.all_paths[idx]
            fitness = ind.fitness.values

            optimised_paths.append({
                'path_index': idx,
                'path': path,
                'target': target_id,
                'target_criticality': target_crit,
                'path_length': len(path),
                'fitness': {
                    'exploitability': round(fitness[0], 3),
                    'impact': round(fitness[1], 3),
                    'time': round(fitness[2], 1),
                    'stealth': round(fitness[3], 3)
                },
                'total_fitness': round(sum(fitness), 3),
                'description': self._describe_path(path)
            })

        optimised_paths.sort(key=lambda x: x['total_fitness'], reverse=True)
        return optimised_paths

    def _describe_path(self, path):
        steps = []
        for i in range(len(path) - 1):
            try:
                edge = self.graph[path[i]][path[i + 1]]
                steps.append(edge.get('description', 'Unknown'))
            except (KeyError, IndexError):
                steps.append('Unknown')
        return ' -> '.join(steps[:4]) + ('...' if len(steps) > 4 else '')

    def visualise_evolution(self, output_file='ga_evolution.png'):
        if not self.evolution_stats['generations']:
            return

        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        gens = self.evolution_stats['generations']

        ax1.plot(gens, self.evolution_stats['best_fitness'], 'b-', linewidth=2)
        ax1.set_xlabel('Generation')
        ax1.set_ylabel('Best Fitness')
        ax1.set_title('Best Fitness Evolution')
        ax1.grid(True, alpha=0.3)

        ax2.plot(gens, self.evolution_stats['avg_fitness'], 'g-', linewidth=2)
        ax2.set_xlabel('Generation')
        ax2.set_ylabel('Average Fitness')
        ax2.set_title('Average Fitness Evolution')
        ax2.grid(True, alpha=0.3)

        ax3.plot(gens, self.evolution_stats['diversity'], 'r-', linewidth=2)
        ax3.set_xlabel('Generation')
        ax3.set_ylabel('Diversity')
        ax3.set_title('Population Diversity')
        ax3.grid(True, alpha=0.3)

        if len(self.evolution_stats['best_fitness']) > 1:
            improvements = np.diff(self.evolution_stats['best_fitness'])
            ax4.plot(gens[1:], improvements, 'purple', linewidth=2)
            ax4.axhline(y=0, color='black', linestyle='--', alpha=0.5)
            ax4.set_xlabel('Generation')
            ax4.set_ylabel('Improvement')
            ax4.set_title('Convergence Rate')
            ax4.grid(True, alpha=0.3)

        plt.suptitle('GA Evolution - Airport Attack Path Optimisation NSGA-II',
                     fontsize=16, fontweight='bold')
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"[+] Saved {output_file}")
        plt.close()

    def export_results(self, optimised_paths, output_file='optimised_attack_paths.json'):
        results = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'algorithm': 'NSGA-II (DEAP)',
                'population_size': self.population_size,
                'generations': self.generations,
                'total_paths_evaluated': len(self.all_paths),
                'pareto_front_size': len(optimised_paths),
                'source_node': self.source_node,
                'target_nodes': [t[0] for t in self.target_nodes],
                'architecture': 'Hub-and-spoke (DCS central)'
            },
            'ga_parameters': {
                'crossover_probability': self.crossover_prob,
                'mutation_probability': self.mutation_prob,
                'selection': 'NSGA-II',
                'fitness_weights': '(exploit+1.0, impact+1.0, time-1.0, stealth+1.0)'
            },
            'optimised_paths': optimised_paths,
            'evolution_stats': self.evolution_stats
        }

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results exported to {output_file}")


def main():
    print("=" * 60)
    print("GA Attack Path Optimiser")
    print("=" * 60 + "\n")

    optimiser = AttackPathOptimiser('attack_graph.json')

    if not optimiser.all_paths:
        print("[-] No valid attack paths. Check attack_graph.json.")
        exit(1)

    optimised_paths = optimiser.run_optimisation()

    if not optimised_paths:
        print("[-] No optimised paths generated.")
        exit(1)

    print("\n" + "=" * 60)
    print("Top Optimised Attack Paths")
    print("=" * 60)
    for i, p in enumerate(optimised_paths[:10], 1):
        print(
            f"\nRank {i}: -> {p['target']} (criticality: {p['target_criticality']})")
        print(f"  Total Fitness: {p['total_fitness']:.3f}")
        print(f"  Exploitability: {p['fitness']['exploitability']:.2f} | "
              f"Impact: {p['fitness']['impact']:.2f} | "
              f"Time: {p['fitness']['time']:.1f}min | "
              f"Stealth: {p['fitness']['stealth']:.3f}")
        print(f"  Hops: {p['path_length']}")
        print(f"  Route: {' -> '.join(p['path'])}")
        print(f"  Description: {p['description']}")

    print("\n" + "=" * 60)
    optimiser.visualise_evolution()
    optimiser.export_results(optimised_paths)
    print("\n" + "=" * 60)
    print("GA Optimisation Complete")
    print("=" * 60)


if __name__ == '__main__':
    main()
