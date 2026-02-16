"""
Genetic Algorithm Attack Path Optimiser
Uses DEAP to optimise attack path selection based on multi-objective fitness

Input: attack_graph.json
Output: optimized_attack_paths.json, ga_evolution.png
"""

import json
import random
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime
from typing import List, Dict, Any, Tuple
import time
import subprocess
import sys
import importlib.util


def check_and_install_deap():
    """Check if DEAP is installed, if not, provide installation instructions"""
    if importlib.util.find_spec("deap") is None:
        print("="*60)
        print("ERROR: DEAP library is not installed!")
        print("="*60)
        print("\nDEAP (Distributed Evolutionary Algorithms in Python) is required for the genetic algorithm.")
        print("\nTo install DEAP, run one of the following commands:")
        print("\n  pip install deap")
        print("  OR")
        print("  pip3 install deap")
        print("  OR")
        print("  conda install -c conda-forge deap")
        print("\nIf you're using a virtual environment, make sure it's activated.")
        print("\nAlternatively, you can install all requirements at once:")
        print("  pip install -r requirements.txt")
        print("\nWould you like to attempt automatic installation? (y/n): ", end="")

        choice = input().strip().lower()
        if choice in ['y', 'yes']:
            try:
                print("\n[*] Attempting to install DEAP via pip...")
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "deap"])
                print("[+] DEAP installed successfully!")
                print("[*] Importing DEAP...")
                global creator, base, tools, algorithms
                from deap import creator, base, tools, algorithms
                return True
            except Exception as e:
                print(f"[-] Failed to install DEAP: {e}")
                print("[!] Please install DEAP manually and try again.")
                sys.exit(1)
        else:
            print("\n[!] Please install DEAP manually and run this script again.")
            sys.exit(1)
    else:
        print("[+] DEAP library found!")
        global creator, base, tools, algorithms
        from deap import creator, base, tools, algorithms
        return True


def check_dependencies():
    """Check if all required packages are installed"""
    required_packages = {
        'numpy': 'numpy',
        'networkx': 'networkx',
        'matplotlib': 'matplotlib'
    }

    missing_packages = []
    for package, import_name in required_packages.items():
        if importlib.util.find_spec(package) is None:
            missing_packages.append(package)

    if missing_packages:
        print("="*60)
        print("ERROR: Missing required packages!")
        print("="*60)
        print(f"\nMissing: {', '.join(missing_packages)}")
        print("\nInstall them with:")
        print(f"  pip install {' '.join(missing_packages)}")
        print("\nOr install all requirements at once:")
        print("  pip install -r requirements.txt")
        sys.exit(1)

    print("[+] All core dependencies found!")


check_dependencies()
check_and_install_deap()


class AttackPathOptimizer:
    """
    Genetic Algorithm optimiser for attack path prioritisation
    """

    def __init__(self, graph_file: str = 'attack_graph.json'):
        self.graph_data = self._load_graph(graph_file)
        self.graph = self._build_networkx_graph()

        self._configure_ga_parameters()

        # Find all valid paths from INITIAL to ADMIN_PANEL
        self.all_paths = self._enumerate_all_paths()

        self._setup_deap()

        self.evolution_stats = {
            'generations': [],
            'best_fitness': [],
            'avg_fitness': [],
            'diversity': []
        }

    def _configure_ga_parameters(self):
        """Configure GA parameters based on the number of paths"""
        try:
            with open('attack_graph.json', 'r') as f:
                data = json.load(f)
            G_temp = nx.DiGraph()
            for node in data['nodes']:
                G_temp.add_node(node['id'])
            for edge in data['edges']:
                G_temp.add_edge(edge['source'], edge['target'])

            if nx.has_path(G_temp, 'INITIAL_STATE', 'ASSET_ADMIN_PANEL'):
                path_count = len(list(nx.all_simple_paths(
                    G_temp, 'INITIAL_STATE', 'ASSET_ADMIN_PANEL')))
            else:
                path_count = 0
        except:
            path_count = 100  # Default guess

        if path_count > 1000:
            self.population_size = 100
            self.generations = 150
        elif path_count > 100:
            self.population_size = 70
            self.generations = 100
        else:
            self.population_size = 50
            self.generations = 50

        self.crossover_prob = 0.7
        self.mutation_prob = 0.2

        print(f"[+] GA Parameters configured for {path_count} paths")
        print(f"    Population: {self.population_size}")
        print(f"    Generations: {self.generations}")

    def _load_graph(self, filename: str) -> Dict[str, Any]:
        """Load attack graph JSON"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            print(f"[+] Loaded attack graph from {filename}")
            print(f"    Nodes: {data['metadata']['total_nodes']}")
            print(f"    Edges: {data['metadata']['total_edges']}")
            return data
        except FileNotFoundError:
            print(f"[-] Graph file not found: {filename}")
            print("[!] Run attack_graph_generator.py first")
            exit(1)
        except json.JSONDecodeError:
            print(f"[-] Invalid JSON in file: {filename}")
            exit(1)

    def _build_networkx_graph(self) -> nx.DiGraph:
        """Rebuild NetworkX graph from JSON"""
        G = nx.DiGraph()

        for node in self.graph_data['nodes']:
            G.add_node(node['id'], **{k: v for k,
                       v in node.items() if k != 'id'})

        for edge in self.graph_data['edges']:
            G.add_edge(
                edge['source'],
                edge['target'],
                **{k: v for k, v in edge.items() if k not in ['source', 'target']}
            )

        print(f"[+] Rebuilt NetworkX graph")
        return G

    def _enumerate_all_paths(self) -> List[List[str]]:
        """Find all simple paths from INITIAL to ADMIN_PANEL"""
        initial = 'INITIAL_STATE'
        target = 'ASSET_ADMIN_PANEL'

        if not nx.has_path(self.graph, initial, target):
            print(f"[-] No path exists from {initial} to {target}")
            return []

        all_paths = list(nx.all_simple_paths(self.graph, initial, target))
        print(f"[+] Found {len(all_paths)} valid attack paths")

        for i, path in enumerate(all_paths[:5], 1):
            path_summary = ' → '.join(path[:3])
            if len(path) > 3:
                path_summary += f" → ... ({len(path)-3} more)"
            print(f"    Path {i}: {len(path)} nodes - {path_summary}")

        return all_paths

    def _setup_deap(self):
        """Configure DEAP framework for GA"""
        if not hasattr(creator, "FitnessMulti"):
            # Fitness definition
            creator.create("FitnessMulti", base.Fitness,
                           weights=(1.0, 1.0, -1.0, 1.0))
        else:
            creator.FitnessMulti = type('FitnessMulti', (base.Fitness,), {
                                        'weights': (1.0, 1.0, -1.0, 1.0)})

        if not hasattr(creator, "Individual"):
            creator.create("Individual", list, fitness=creator.FitnessMulti)

        self.toolbox = base.Toolbox()

        # Random path index
        self.toolbox.register("attr_path", random.randint,
                              0, max(0, len(self.all_paths) - 1))

        # Individual: Single path index wrapped in list
        self.toolbox.register("individual", tools.initRepeat, creator.Individual,
                              self.toolbox.attr_path, n=1)

        # Population
        self.toolbox.register("population", tools.initRepeat, list,
                              self.toolbox.individual)

        self.toolbox.register("evaluate", self._fitness_function)
        self.toolbox.register("mate", self._crossover)
        self.toolbox.register("mutate", self._mutate)
        self.toolbox.register("select", tools.selNSGA2)

        print(f"[+] DEAP configured successfully")

    def _fitness_function(self, individual: List[int]) -> Tuple[float, float, float, float]:
        """
        Multi-objective fitness function

        Returns: exploitability, impact, time, stealth
        """
        path_index = individual[0]

        # Handle edge case
        if not self.all_paths or path_index >= len(self.all_paths):
            return (0.0, 0.0, 1000.0, 0.0)

        path = self.all_paths[path_index]

        exploitability_scores = []
        impact_scores = []
        time_estimates = []

        # Traverse path edges
        for i in range(len(path) - 1):
            try:
                edge_data = self.graph[path[i]][path[i + 1]]

                exploitability_scores.append(
                    edge_data.get('exploitability', 0.5))
                impact_scores.append(edge_data.get('impact', 0.5))
                time_estimates.append(edge_data.get('time_estimate', 10.0))
            except KeyError:
                # Edge not found, use default values
                exploitability_scores.append(0.3)
                impact_scores.append(0.3)
                time_estimates.append(15.0)

        # Calculate objectives
        exploitability = min(
            exploitability_scores) if exploitability_scores else 0.0
        impact = np.prod(impact_scores) if impact_scores else 0.0
        time = sum(time_estimates)
        stealth = 1.0 / len(path) if len(path) > 1 else 0.0

        return (exploitability, impact, time, stealth)

    def _crossover(self, ind1: List[int], ind2: List[int]) -> Tuple[List[int], List[int]]:
        """
        Single-point crossover for path indices
        """
        # For single-gene individuals, swap paths
        if random.random() < 0.5:
            ind1[0], ind2[0] = ind2[0], ind1[0]

        return ind1, ind2

    def _mutate(self, individual: List[int]) -> Tuple[List[int]]:
        """
        Mutation: Change to a random path
        """
        individual[0] = random.randint(0, max(0, len(self.all_paths) - 1))
        return (individual,)

    def run_optimization(self) -> List[Dict[str, Any]]:
        """
        Run GA optimization
        Returns list of optimized attack paths
        """
        if not self.all_paths:
            print("[-] No attack paths to optimise!")
            return []

        print("\n" + "="*60)
        print("Running Genetic Algorithm Optimisation")
        print("="*60 + "\n")

        # Initialise and evaluate population
        population = self.toolbox.population(n=self.population_size)
        fitnesses = list(map(self.toolbox.evaluate, population))
        for ind, fit in zip(population, fitnesses):
            ind.fitness.values = fit

        print(f"[*] Generation 0/{self.generations}")
        print(f"    Population size: {len(population)}")

        start_time = time.time()

        for gen in range(1, self.generations + 1):
            offspring = self.toolbox.select(population, len(population))
            offspring = list(map(self.toolbox.clone, offspring))

            # Apply crossover
            for child1, child2 in zip(offspring[::2], offspring[1::2]):
                if random.random() < self.crossover_prob:
                    self.toolbox.mate(child1, child2)
                    del child1.fitness.values
                    del child2.fitness.values

            # Apply mutation
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

                # Unique path indices
                diversity = len(set(ind[0]
                                for ind in population)) / max(1, len(self.all_paths))

                self.evolution_stats['generations'].append(gen)
                self.evolution_stats['best_fitness'].append(sum(best_fit))
                self.evolution_stats['avg_fitness'].append(sum(avg_fit))
                self.evolution_stats['diversity'].append(diversity)

                if gen % 10 == 0 or gen == 1:
                    print(f"[*] Generation {gen}/{self.generations}")
                    print(f"    Best fitness: {sum(best_fit):.3f}")
                    print(f"    Avg fitness: {sum(avg_fit):.3f}")
                    print(f"    Diversity: {diversity:.2%}")

        elapsed_time = time.time() - start_time
        print(f"\n[+] Optimization complete in {elapsed_time:.2f} seconds")

        # Extract Pareto front
        valid_population = [ind for ind in population if ind.fitness.valid]
        if valid_population:
            pareto_front = tools.sortNondominated(
                valid_population, len(valid_population), first_front_only=True)[0]
            print(f"[+] Pareto front size: {len(pareto_front)}")
        else:
            pareto_front = []
            print("[-] No valid individuals in final population")

        # Convert to readable results
        optimized_paths = []
        for ind in pareto_front[:10]:
            path_index = ind[0]
            if path_index < len(self.all_paths):
                path = self.all_paths[path_index]
                fitness = ind.fitness.values

                optimized_paths.append({
                    'path_index': path_index,
                    'path': path,
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

        optimized_paths.sort(key=lambda x: x['total_fitness'], reverse=True)

        return optimized_paths

    def _describe_path(self, path: List[str]) -> str:
        """Generate human-readable path description"""
        steps = []
        for i in range(len(path) - 1):
            try:
                edge_data = self.graph[path[i]][path[i + 1]]
                steps.append(edge_data.get('description', 'Unknown action'))
            except KeyError:
                steps.append('Unknown action')

        return ' → '.join(steps[:3]) + ('...' if len(steps) > 3 else '')

    def visualize_evolution(self, output_file: str = 'ga_evolution.png'):
        """Plot GA evolution statistics"""
        if not self.evolution_stats['generations']:
            print("[-] No evolution data to visualize")
            return

        try:
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(
                2, 2, figsize=(14, 10))

            generations = self.evolution_stats['generations']

            # Plot 1: Best fitness over time
            ax1.plot(
                generations, self.evolution_stats['best_fitness'], 'b-', linewidth=2)
            ax1.set_xlabel('Generation')
            ax1.set_ylabel('Best Fitness')
            ax1.set_title('Best Fitness Evolution')
            ax1.grid(True, alpha=0.3)

            # Plot 2: Average fitness over time
            if self.evolution_stats['avg_fitness']:
                ax2.plot(
                    generations, self.evolution_stats['avg_fitness'], 'g-', linewidth=2)
                ax2.set_xlabel('Generation')
                ax2.set_ylabel('Average Fitness')
                ax2.set_title('Average Fitness Evolution')
                ax2.grid(True, alpha=0.3)

            # Plot 3: Diversity over time
            if self.evolution_stats['diversity']:
                ax3.plot(
                    generations, self.evolution_stats['diversity'], 'r-', linewidth=2)
                ax3.set_xlabel('Generation')
                ax3.set_ylabel('Population Diversity')
                ax3.set_title('Population Diversity (% of unique paths)')
                ax3.grid(True, alpha=0.3)

            # Plot 4: Convergence rate
            if len(self.evolution_stats['best_fitness']) > 1:
                improvements = np.diff(self.evolution_stats['best_fitness'])
                ax4.plot(generations[1:], improvements, 'purple', linewidth=2)
                ax4.axhline(y=0, color='black', linestyle='--', alpha=0.5)
                ax4.set_xlabel('Generation')
                ax4.set_ylabel('Fitness Improvement')
                ax4.set_title('Convergence Rate')
                ax4.grid(True, alpha=0.3)

            plt.suptitle('Genetic Algorithm Evolution - Attack Path Optimisation',
                         fontsize=16, fontweight='bold')
            plt.tight_layout()
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            print(f"[+] Evolution visualisation saved to {output_file}")
            plt.close()
        except Exception as e:
            print(f"[-] Error creating visualisation: {e}")

    def export_results(self, optimized_paths: List[Dict[str, Any]],
                       output_file: str = 'optimized_attack_paths.json'):
        """Export optimization results"""
        results = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'algorithm': 'Genetic Algorithm (DEAP)',
                'population_size': self.population_size,
                'generations': self.generations,
                'total_paths_evaluated': len(self.all_paths),
                'pareto_front_size': len(optimized_paths)
            },
            'ga_parameters': {
                'crossover_probability': self.crossover_prob,
                'mutation_probability': self.mutation_prob,
                'selection': 'NSGA-II'
            },
            'optimized_paths': optimized_paths,
            'evolution_stats': {
                'generations': self.evolution_stats['generations'],
                'best_fitness': self.evolution_stats['best_fitness'],
                'avg_fitness': self.evolution_stats['avg_fitness'],
                'diversity': self.evolution_stats['diversity']
            }
        }

        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"[+] Results exported to {output_file}")
        except Exception as e:
            print(f"[-] Error exporting results: {e}")


def create_requirements_file():
    """Create requirements.txt if it doesn't exist"""
    requirements = """deap>=1.3.1
networkx>=2.6
numpy>=1.21
matplotlib>=3.4
"""
    try:
        with open('requirements.txt', 'x') as f:
            f.write(requirements)
        print("[+] Created requirements.txt file")
    except FileExistsError:
        pass  # File already exists


def main():
    """
    Main execution: Run GA optimization
    """
    print("="*60)
    print("Genetic Algorithm Attack Path Optimiser")
    print("="*60)
    print()
    create_requirements_file()

    optimizer = AttackPathOptimizer('attack_graph.json')

    if len(optimizer.all_paths) == 0:
        print("[-] No valid attack paths found. Cannot optimize.")
        exit(1)

    print()

    optimized_paths = optimizer.run_optimization()

    if not optimized_paths:
        print("[-] No optimized paths generated.")
        exit(1)

    for i, path_info in enumerate(optimized_paths[:5], 1):
        print(f"Rank {i}:")
        print(f"  Total Fitness: {path_info['total_fitness']:.3f}")
        print(f"  Path Length: {path_info['path_length']} hops")
        print(
            f"  Exploitability: {path_info['fitness']['exploitability']:.2f}")
        print(f"  Impact: {path_info['fitness']['impact']:.2f}")
        print(f"  Time: {path_info['fitness']['time']:.1f} minutes")
        print(f"  Stealth: {path_info['fitness']['stealth']:.3f}")
        print(f"  Route: {' → '.join(path_info['path'])}")
        print(f"  Description: {path_info['description']}")
        print()

    print("="*60)
    print("Generating Visualizations")
    print("="*60)
    print()
    optimizer.visualize_evolution()

    # Export results
    print()
    print("="*60)
    print("Exporting Results")
    print("="*60)
    print()
    optimizer.export_results(optimized_paths)

    print()
    print("="*60)
    print("GA Optimisation Complete!")
    print("="*60)
    print("\nOutput files:")
    print("  - optimized_attack_paths.json")
    print("  - ga_evolution.png")
    print("\nNext: Phase 5 - Comparative Evaluation")
    print("  Compare: Manual vs CVSS-only vs GA-optimized")
    print("="*60)


if __name__ == '__main__':
    main()
