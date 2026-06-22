from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
import math
from typing import DefaultDict

from nsec3_candidate_scheduler.feedback.normalize import normalize_dns_name


def trigrams(s: str) -> list[str]:
    s = s.lower()
    if len(s) < 3:
        return [s]
    return [s[i:i+3] for i in range(len(s)-2)]


def cosine_sim(a: Counter, b: Counter) -> float:
    denom = math.sqrt(sum(v*v for v in a.values())) * math.sqrt(sum(v*v for v in b.values()))
    if denom == 0:
        return 0.0
    return sum(a[k] * b.get(k, 0) for k in a) / denom


class PredictiveModel:
    def __init__(self) -> None:
        self.counts: DefaultDict[str, Counter[str]] = defaultdict(Counter)
        self.prediction_totals: Counter[str] = Counter()
        self.source_vecs: dict[str, Counter[str]] = {}
        self.gram_index: DefaultDict[str, set[str]] = defaultdict(set)

    @classmethod
    def load_tsv(cls, path: str) -> 'PredictiveModel':
        model = cls()
        with Path(path).open('r', encoding='utf-8', errors='replace') as f:
            for line in f:
                parts = line.rstrip('\n').split('\t')
                if len(parts) != 3:
                    continue
                source = normalize_dns_name(parts[0])
                pred = normalize_dns_name(parts[1])
                try:
                    count = int(parts[2])
                except ValueError:
                    continue
                if source is None or pred is None or count <= 0:
                    continue
                model.counts[source][pred] += count
                model.prediction_totals[pred] += count
        for source in model.counts:
            vec = Counter(trigrams(source))
            model.source_vecs[source] = vec
            for gram in vec:
                model.gram_index[gram].add(source)
        return model

    def predict(self, source: str, min_sim: float = 0.7, tau: float = 2.0, gamma: float = 0.0,
                score_floor: float = -5.0, k_neighbors: int = 30, top_predictions_per_neighbor: int = 100,
                max_predictions: int = 100) -> list[str]:
        normalized = normalize_dns_name(source)
        if normalized is None:
            return []
        src_vec = Counter(trigrams(normalized))
        candidates: set[str] = set()
        for gram in src_vec:
            candidates.update(self.gram_index.get(gram, set()))
        neighbors: list[tuple[str, float]] = []
        for cand in candidates:
            sim = cosine_sim(src_vec, self.source_vecs[cand])
            if sim >= min_sim:
                neighbors.append((cand, sim))
        neighbors.sort(key=lambda x: (-x[1], x[0]))
        neighbors = neighbors[:k_neighbors]
        if normalized in self.counts:
            neighbors = [(n, s) for n, s in neighbors if n != normalized]
            neighbors.insert(0, (normalized, 1.0))
            neighbors = neighbors[:k_neighbors]
        agg: Counter[str] = Counter()
        for neighbor, sim in neighbors:
            weight = sim ** tau
            for prediction, count in self.counts[neighbor].most_common(top_predictions_per_neighbor):
                agg[prediction] += weight * count
        scored = []
        for prediction, value in agg.items():
            score = math.log(1 + value) - gamma * math.log(1 + self.prediction_totals[prediction])
            if score > score_floor:
                scored.append((prediction, score))
        scored.sort(key=lambda x: (-x[1], x[0]))
        return [p for p, _ in scored[:max_predictions]]
