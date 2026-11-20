import heapq
import networkx as nx

def build_network_graph():
    """Models the bank network with lateral-movement traversal costs."""
    G = nx.DiGraph()
    edges = [
        ("public_portal", "dmz_gateway", 2),
        ("public_portal", "web_proxy", 4),
        ("dmz_gateway", "app_server", 3),
        ("web_proxy", "app_server", 2),
        ("app_server", "internal_auth", 2),
        ("app_server", "core_db", 6),
        ("internal_auth", "core_db", 2),
        ("core_db", "credit_cards_db", 1),
    ]
    for src, dst, cost in edges:
        G.add_edge(src, dst, weight=cost)

    # Heuristic: estimated remaining hops/cost to reach credit_cards_db
    heuristics = {
        "public_portal": 8,
        "dmz_gateway": 6,
        "web_proxy": 5,
        "app_server": 4,
        "internal_auth": 2,
        "core_db": 1,
        "credit_cards_db": 0,
    }
    return G, heuristics

def uniform_cost_search(graph, start, goal):
    """Finds the lowest cumulative-cost path using UCS."""
    frontier = [(0, start, [start])]
    explored = set()
    nodes_expanded = 0

    while frontier:
        cost, current, path = heapq.heappop(frontier)
        if current in explored:
            continue
        explored.add(current)
        nodes_expanded += 1

        if current == goal:
            return path, cost, nodes_expanded

        for neighbor in graph.neighbors(current):
            if neighbor not in explored:
                edge_cost = graph[current][neighbor]["weight"]
                heapq.heappush(frontier, (cost + edge_cost, neighbor, path + [neighbor]))

    return None, float("inf"), nodes_expanded

def a_star_search(graph, heuristics, start, goal):
    """Finds the optimal path using f(n) = g(n) + h(n)."""
    frontier = [(heuristics[start], 0, start, [start])]
    best_g = {start: 0}
    nodes_expanded = 0

    while frontier:
        f_cost, g_cost, current, path = heapq.heappop(frontier)
        nodes_expanded += 1

        if current == goal:
            return path, g_cost, nodes_expanded

        for neighbor in graph.neighbors(current):
            new_g = g_cost + graph[current][neighbor]["weight"]
            if new_g < best_g.get(neighbor, float("inf")):
                best_g[neighbor] = new_g
                new_f = new_g + heuristics[neighbor]
                heapq.heappush(frontier, (new_f, new_g, neighbor, path + [neighbor]))

    return None, float("inf"), nodes_expanded

if __name__ == "__main__":
    G, h = build_network_graph()
    ucs_path, ucs_cost, ucs_nodes = uniform_cost_search(G, "public_portal", "credit_cards_db")
    astar_path, astar_cost, astar_nodes = a_star_search(G, h, "public_portal", "credit_cards_db")

    print(f"UCS Path: {' -> '.join(ucs_path)} | Cost: {ucs_cost} | Nodes Expanded: {ucs_nodes}")
    print(f"A*  Path: {' -> '.join(astar_path)} | Cost: {astar_cost} | Nodes Expanded: {astar_nodes}")