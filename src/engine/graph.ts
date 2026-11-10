import type { NodeId } from './types';

/** Shortest hop path between two nodes over the lesson's links (BFS). */
export function findPath(links: [NodeId, NodeId][], from: NodeId, to: NodeId): NodeId[] {
  if (from === to) return [from];
  const adj = new Map<NodeId, NodeId[]>();
  for (const [a, b] of links) {
    adj.set(a, [...(adj.get(a) ?? []), b]);
    adj.set(b, [...(adj.get(b) ?? []), a]);
  }
  const prev = new Map<NodeId, NodeId>();
  const queue = [from];
  const seen = new Set([from]);
  while (queue.length) {
    const cur = queue.shift()!;
    if (cur === to) break;
    for (const n of adj.get(cur) ?? []) {
      if (seen.has(n)) continue;
      seen.add(n);
      prev.set(n, cur);
      queue.push(n);
    }
  }
  if (!seen.has(to)) return [from, to];
  const path = [to];
  while (path[0] !== from) path.unshift(prev.get(path[0])!);
  return path;
}
