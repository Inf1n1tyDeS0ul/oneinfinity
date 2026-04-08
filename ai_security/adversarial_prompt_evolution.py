"""
Adversarial Prompt Evolution Engine — self-improving attack prompt generation.

Learning pipeline:
  prompt → target → response → analysis → success/failure → update strategy → generate improved prompts

Stores:
  - All prompt→result pairs in SQLite
  - Success rates per strategy/mutation type
  - High-performing prompt "seeds"
  - Cross-target pattern library

Evolution strategies:
  1. Fitness-based selection — promote high-scoring prompts
  2. Crossover              — combine elements from multiple successful prompts
  3. Guided mutation        — apply mutations that historically work
  4. Novelty search         — explore prompt space, avoid clustering
  5. Tournament selection   — compare prompt variants, keep winners
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from path_manager import db_path as db_path_fn

from .prompt_generator import AdversarialPrompt, PromptGenerator
from .payload_mutator import PayloadMutator, MutatedPrompt
from .vulnerability_detector import AIVulnFinding

log = logging.getLogger(__name__)

_DB_PATH = db_path_fn("prompt_evolution.db")


# ─────────────────────────────────────────────────────────────────────────────
#  Prompt gene
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PromptGene:
    """A prompt with its evolutionary metadata."""
    prompt_id: str
    text: str
    attack_type: str
    source: str                    # "seed" | "mutation" | "crossover" | "ai"
    parent_ids: List[str]          # lineage
    generation: int
    mutation_type: str             # which mutation was applied
    times_tested: int = 0
    times_succeeded: int = 0
    last_success_score: float = 0.0
    fitness: float = 0.0          # computed: success_rate × avg_score

    @property
    def success_rate(self) -> float:
        if self.times_tested == 0:
            return 0.0
        return self.times_succeeded / self.times_tested

    def update_fitness(self) -> None:
        self.fitness = self.success_rate * (0.7 + 0.3 * self.last_success_score)


# ─────────────────────────────────────────────────────────────────────────────
#  Evolution DB
# ─────────────────────────────────────────────────────────────────────────────

class EvolutionDB:
    """SQLite persistence for the evolution engine, with PG-first fallback."""

    def _pg(self):
        """Return DBManager if PG/distributed mode is available, else None."""
        try:
            from core.db_manager import get_db_manager_sync
            mgr = get_db_manager_sync()
            return mgr if mgr and mgr.mode in ("distributed", "postgres") else None
        except Exception:
            return None

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._path = db_path or _DB_PATH
        mgr = self._pg()
        if mgr is not None:
            self._conn = None
        else:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        if self._pg() is not None:
            # Tables already managed in db/schema.sql
            return
        self._conn.executescript("""
        CREATE TABLE IF NOT EXISTS prompt_genes (
            prompt_id       TEXT PRIMARY KEY,
            text            TEXT NOT NULL,
            attack_type     TEXT NOT NULL,
            source          TEXT NOT NULL,
            parent_ids      TEXT DEFAULT '[]',
            generation      INTEGER DEFAULT 0,
            mutation_type   TEXT DEFAULT '',
            times_tested    INTEGER DEFAULT 0,
            times_succeeded INTEGER DEFAULT 0,
            last_success_score REAL DEFAULT 0.0,
            fitness         REAL DEFAULT 0.0,
            created_at      REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS test_results (
            result_id       TEXT PRIMARY KEY,
            prompt_id       TEXT NOT NULL,
            target          TEXT NOT NULL,
            response_hash   TEXT NOT NULL,
            success         INTEGER NOT NULL,
            score           REAL NOT NULL,
            attack_type     TEXT NOT NULL,
            mutation_type   TEXT DEFAULT '',
            tested_at       REAL NOT NULL,
            FOREIGN KEY(prompt_id) REFERENCES prompt_genes(prompt_id)
        );

        CREATE TABLE IF NOT EXISTS strategy_stats (
            strategy        TEXT NOT NULL,
            attack_type     TEXT NOT NULL,
            total_attempts  INTEGER DEFAULT 0,
            total_successes INTEGER DEFAULT 0,
            avg_score       REAL DEFAULT 0.0,
            PRIMARY KEY(strategy, attack_type)
        );

        CREATE INDEX IF NOT EXISTS idx_attack_type ON prompt_genes(attack_type);
        CREATE INDEX IF NOT EXISTS idx_fitness ON prompt_genes(fitness DESC);
        CREATE INDEX IF NOT EXISTS idx_target ON test_results(target);
        """)
        self._conn.commit()

    def save_gene(self, gene: PromptGene) -> None:
        mgr = self._pg()
        if mgr is not None:
            mgr.sync_pg_execute_write("""
                INSERT INTO prompt_genes
                    (prompt_id, text, attack_type, source, parent_ids, generation,
                     mutation_type, times_tested, times_succeeded, last_success_score,
                     fitness, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (prompt_id) DO UPDATE SET
                    text                = EXCLUDED.text,
                    attack_type         = EXCLUDED.attack_type,
                    source              = EXCLUDED.source,
                    parent_ids          = EXCLUDED.parent_ids,
                    generation          = EXCLUDED.generation,
                    mutation_type       = EXCLUDED.mutation_type,
                    times_tested        = EXCLUDED.times_tested,
                    times_succeeded     = EXCLUDED.times_succeeded,
                    last_success_score  = EXCLUDED.last_success_score,
                    fitness             = EXCLUDED.fitness,
                    created_at          = EXCLUDED.created_at
            """, (
                gene.prompt_id, gene.text, gene.attack_type, gene.source,
                json.dumps(gene.parent_ids), gene.generation, gene.mutation_type,
                gene.times_tested, gene.times_succeeded, gene.last_success_score,
                gene.fitness, time.time()
            ))
        else:
            self._conn.execute("""
                INSERT OR REPLACE INTO prompt_genes VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                gene.prompt_id, gene.text, gene.attack_type, gene.source,
                json.dumps(gene.parent_ids), gene.generation, gene.mutation_type,
                gene.times_tested, gene.times_succeeded, gene.last_success_score,
                gene.fitness, time.time()
            ))
            self._conn.commit()

    def load_gene(self, prompt_id: str) -> Optional[PromptGene]:
        mgr = self._pg()
        if mgr is not None:
            rows = mgr.sync_pg_execute_read(
                "SELECT * FROM prompt_genes WHERE prompt_id = %s", (prompt_id,)
            )
            if not rows:
                return None
            return self._row_to_gene(rows[0])
        else:
            row = self._conn.execute(
                "SELECT * FROM prompt_genes WHERE prompt_id = ?", (prompt_id,)
            ).fetchone()
            if row is None:
                return None
            return self._row_to_gene(row)

    def update_gene_stats(
        self, prompt_id: str, succeeded: bool, score: float
    ) -> None:
        mgr = self._pg()
        if mgr is not None:
            mgr.sync_pg_execute_write("""
                UPDATE prompt_genes
                SET times_tested = times_tested + 1,
                    times_succeeded = times_succeeded + %s,
                    last_success_score = %s,
                    fitness = (CAST(times_succeeded + %s AS REAL) / (times_tested + 1)) * (0.7 + 0.3 * %s)
                WHERE prompt_id = %s
            """, (int(succeeded), score, int(succeeded), score, prompt_id))
        else:
            self._conn.execute("""
                UPDATE prompt_genes
                SET times_tested = times_tested + 1,
                    times_succeeded = times_succeeded + ?,
                    last_success_score = ?,
                    fitness = (CAST(times_succeeded + ? AS REAL) / (times_tested + 1)) * (0.7 + 0.3 * ?)
                WHERE prompt_id = ?
            """, (int(succeeded), score, int(succeeded), score, prompt_id))
            self._conn.commit()

    def record_result(
        self, prompt_id: str, target: str, response_hash: str,
        success: bool, score: float, attack_type: str, mutation_type: str
    ) -> None:
        import uuid
        result_id = uuid.uuid4().hex[:12]
        mgr = self._pg()
        if mgr is not None:
            mgr.sync_pg_execute_write("""
                INSERT INTO test_results
                    (result_id, prompt_id, target, response_hash, success,
                     score, attack_type, mutation_type, tested_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                result_id, prompt_id, target, response_hash,
                int(success), score, attack_type, mutation_type, time.time()
            ))
            mgr.sync_pg_execute_write("""
                INSERT INTO strategy_stats
                    (strategy, attack_type, total_attempts, total_successes, avg_score)
                VALUES (%s, %s, 1, %s, %s)
                ON CONFLICT (strategy, attack_type) DO UPDATE SET
                    total_attempts  = strategy_stats.total_attempts + 1,
                    total_successes = strategy_stats.total_successes + %s,
                    avg_score       = (strategy_stats.avg_score * strategy_stats.total_attempts + %s)
                                      / (strategy_stats.total_attempts + 1)
            """, (
                mutation_type, attack_type, int(success), score,
                int(success), score
            ))
        else:
            self._conn.execute("""
                INSERT INTO test_results VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                result_id, prompt_id, target, response_hash,
                int(success), score, attack_type, mutation_type, time.time()
            ))
            self._conn.commit()
            # Update strategy stats
            self._conn.execute("""
                INSERT INTO strategy_stats (strategy, attack_type, total_attempts, total_successes, avg_score)
                VALUES (?, ?, 1, ?, ?)
                ON CONFLICT(strategy, attack_type) DO UPDATE SET
                    total_attempts = total_attempts + 1,
                    total_successes = total_successes + ?,
                    avg_score = (avg_score * total_attempts + ?) / (total_attempts + 1)
            """, (
                mutation_type, attack_type, int(success), score,
                int(success), score
            ))
            self._conn.commit()

    def top_genes(
        self, attack_type: Optional[str] = None,
        limit: int = 50, min_tests: int = 1
    ) -> List[PromptGene]:
        mgr = self._pg()
        if mgr is not None:
            if attack_type:
                rows = mgr.sync_pg_execute_read(
                    "SELECT * FROM prompt_genes WHERE times_tested >= %s AND attack_type = %s"
                    " ORDER BY fitness DESC LIMIT %s",
                    (min_tests, attack_type, limit)
                )
            else:
                rows = mgr.sync_pg_execute_read(
                    "SELECT * FROM prompt_genes WHERE times_tested >= %s"
                    " ORDER BY fitness DESC LIMIT %s",
                    (min_tests, limit)
                )
            return [self._row_to_gene(r) for r in rows]
        else:
            query = "SELECT * FROM prompt_genes WHERE times_tested >= ?"
            params: list = [min_tests]
            if attack_type:
                query += " AND attack_type = ?"
                params.append(attack_type)
            query += " ORDER BY fitness DESC LIMIT ?"
            params.append(limit)
            rows = self._conn.execute(query, params).fetchall()
            return [self._row_to_gene(r) for r in rows]

    def top_strategies(self, attack_type: Optional[str] = None) -> List[Dict]:
        mgr = self._pg()
        if mgr is not None:
            if attack_type:
                rows = mgr.sync_pg_execute_read(
                    "SELECT * FROM strategy_stats WHERE attack_type = %s"
                    " ORDER BY CAST(total_successes AS REAL)/GREATEST(total_attempts,1) DESC LIMIT 10",
                    (attack_type,)
                )
            else:
                rows = mgr.sync_pg_execute_read(
                    "SELECT * FROM strategy_stats"
                    " ORDER BY CAST(total_successes AS REAL)/GREATEST(total_attempts,1) DESC LIMIT 10",
                    ()
                )
            return rows  # already list[dict]
        else:
            query = "SELECT * FROM strategy_stats"
            params = []
            if attack_type:
                query += " WHERE attack_type = ?"
                params.append(attack_type)
            query += " ORDER BY CAST(total_successes AS REAL)/MAX(total_attempts,1) DESC LIMIT 10"
            rows = self._conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def stats(self) -> Dict[str, Any]:
        mgr = self._pg()
        if mgr is not None:
            total       = (mgr.sync_pg_execute_read("SELECT COUNT(*) AS c FROM prompt_genes", ()) or [{"c": 0}])[0]["c"]
            tested      = (mgr.sync_pg_execute_read("SELECT COUNT(*) AS c FROM prompt_genes WHERE times_tested > 0", ()) or [{"c": 0}])[0]["c"]
            high_fitness= (mgr.sync_pg_execute_read("SELECT COUNT(*) AS c FROM prompt_genes WHERE fitness > 0.5", ()) or [{"c": 0}])[0]["c"]
            total_results=(mgr.sync_pg_execute_read("SELECT COUNT(*) AS c FROM test_results", ()) or [{"c": 0}])[0]["c"]
            successes   = (mgr.sync_pg_execute_read("SELECT COUNT(*) AS c FROM test_results WHERE success = 1", ()) or [{"c": 0}])[0]["c"]
        else:
            total        = self._conn.execute("SELECT COUNT(*) FROM prompt_genes").fetchone()[0]
            tested       = self._conn.execute("SELECT COUNT(*) FROM prompt_genes WHERE times_tested > 0").fetchone()[0]
            high_fitness = self._conn.execute("SELECT COUNT(*) FROM prompt_genes WHERE fitness > 0.5").fetchone()[0]
            total_results= self._conn.execute("SELECT COUNT(*) FROM test_results").fetchone()[0]
            successes    = self._conn.execute("SELECT COUNT(*) FROM test_results WHERE success = 1").fetchone()[0]
        return {
            "total_genes": total,
            "tested_genes": tested,
            "high_fitness_genes": high_fitness,
            "total_tests": total_results,
            "total_successes": successes,
            "success_rate": round(successes / max(total_results, 1), 3),
        }

    @staticmethod
    def _row_to_gene(row) -> PromptGene:
        """Convert a sqlite3.Row or a dict (from PG) to a PromptGene."""
        if isinstance(row, dict):
            get = row.get
        else:
            get = lambda k, default=None: row[k] if k in row.keys() else default  # noqa: E731
        parent_ids_raw = get("parent_ids") or "[]"
        if isinstance(parent_ids_raw, list):
            parent_ids = parent_ids_raw
        else:
            parent_ids = json.loads(parent_ids_raw)
        return PromptGene(
            prompt_id=get("prompt_id"),
            text=get("text"),
            attack_type=get("attack_type"),
            source=get("source"),
            parent_ids=parent_ids,
            generation=get("generation") or 0,
            mutation_type=get("mutation_type") or "",
            times_tested=get("times_tested") or 0,
            times_succeeded=get("times_succeeded") or 0,
            last_success_score=get("last_success_score") or 0.0,
            fitness=get("fitness") or 0.0,
        )


# ─────────────────────────────────────────────────────────────────────────────
#  Evolution Engine
# ─────────────────────────────────────────────────────────────────────────────

class AdversarialPromptEvolution:
    """
    Self-evolving adversarial prompt generator.

    Uses genetic algorithm principles:
    - Fitness = success_rate × score
    - Selection = tournament selection from top-k
    - Crossover = combine segments from two parent prompts
    - Mutation = PayloadMutator strategies (fitness-weighted)
    - Novelty = penalize prompts similar to existing ones
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
        population_size: int = 200,
        seed: int = 0,
    ) -> None:
        self._db = EvolutionDB(db_path)
        self._generator = PromptGenerator(seed=seed)
        self._mutator = PayloadMutator(seed=seed)
        self._rng = random.Random(seed)
        self._population_size = population_size
        self._generation = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def seed_population(
        self, attack_type: str = "all", count: int = 100
    ) -> List[PromptGene]:
        """Seed the initial population from templates."""
        prompts = self._generator.generate(attack_type, count)
        genes = []
        for p in prompts:
            gene = self._to_gene(p, source="seed", generation=0)
            self._db.save_gene(gene)
            genes.append(gene)
        log.info("Seeded %d initial prompts for attack_type=%s", len(genes), attack_type)
        return genes

    def record_result(
        self,
        prompt_id: str,
        target: str,
        response: str,
        succeeded: bool,
        score: float,
        mutation_type: str = "",
        attack_type: str = "",
    ) -> None:
        """Record a test result and update gene fitness."""
        response_hash = hashlib.sha256(response.encode()).hexdigest()[:16]
        self._db.update_gene_stats(prompt_id, succeeded, score)
        gene = self._db.load_gene(prompt_id)
        self._db.record_result(
            prompt_id=prompt_id,
            target=target,
            response_hash=response_hash,
            success=succeeded,
            score=score,
            attack_type=attack_type or (gene.attack_type if gene else ""),
            mutation_type=mutation_type,
        )

    def evolve(
        self,
        attack_type: Optional[str] = None,
        num_offspring: int = 50,
    ) -> List[PromptGene]:
        """
        Run one evolution generation.
        Returns new offspring genes (already saved to DB).
        """
        self._generation += 1
        parents = self._db.top_genes(attack_type=attack_type, limit=20, min_tests=1)

        if len(parents) < 2:
            # Not enough data yet — generate fresh seeds
            return self.seed_population(attack_type or "all", num_offspring)

        offspring: List[PromptGene] = []
        top_strategies = self._db.top_strategies(attack_type)
        best_strategies = [s["strategy"] for s in top_strategies[:5]] or None

        for _ in range(num_offspring):
            op = self._rng.random()

            if op < 0.4 and len(parents) >= 2:
                # Crossover
                p1 = self._tournament_select(parents)
                p2 = self._tournament_select(parents)
                child = self._crossover(p1, p2, attack_type)
            elif op < 0.8:
                # Mutation
                parent = self._tournament_select(parents)
                child = self._mutate_gene(parent, best_strategies)
            else:
                # Fresh template (novelty)
                prompt = self._generator.generate(attack_type or "all", 1)[0]
                child = self._to_gene(prompt, source="seed", generation=self._generation)

            self._db.save_gene(child)
            offspring.append(child)

        log.info("Generation %d: created %d offspring", self._generation, len(offspring))
        return offspring

    def get_best_prompts(
        self,
        attack_type: Optional[str] = None,
        count: int = 20,
    ) -> List[str]:
        """Return top-performing prompt texts."""
        genes = self._db.top_genes(attack_type=attack_type, limit=count, min_tests=1)
        if len(genes) < count:
            # Fill with fresh seeds
            fresh = self._generator.generate(attack_type or "all", count - len(genes))
            return [g.text for g in genes] + [p.text for p in fresh]
        return [g.text for g in genes]

    def get_evolved_prompts(
        self,
        attack_type: Optional[str] = None,
        count: int = 50,
        auto_evolve: bool = True,
    ) -> List[AdversarialPrompt]:
        """
        Return evolved prompts for use in a campaign.
        Auto-evolves if population is small.
        """
        top = self._db.top_genes(attack_type, limit=count, min_tests=0)
        if len(top) < count // 2 or auto_evolve:
            new_genes = self.evolve(attack_type, num_offspring=max(count, 50))
            top.extend(new_genes)

        self._rng.shuffle(top)
        return [
            AdversarialPrompt(
                text=g.text,
                attack_type=g.attack_type,
                category="evolved",
                severity="high",
                source="evolved",
                tags=[g.attack_type, "evolved", f"gen{g.generation}"],
            )
            for g in top[:count]
        ]

    def stats(self) -> Dict[str, Any]:
        return {
            "db_stats": self._db.stats(),
            "generation": self._generation,
            "top_strategies": self._db.top_strategies(),
        }

    # ── Evolution operators ───────────────────────────────────────────────────

    def _tournament_select(
        self, population: List[PromptGene], tournament_size: int = 3
    ) -> PromptGene:
        candidates = self._rng.sample(population, min(tournament_size, len(population)))
        return max(candidates, key=lambda g: g.fitness)

    def _crossover(
        self,
        parent1: PromptGene,
        parent2: PromptGene,
        attack_type: Optional[str],
    ) -> PromptGene:
        """Single-point crossover on sentence boundaries."""
        sentences1 = re.split(r'(?<=[.!?])\s+', parent1.text)
        sentences2 = re.split(r'(?<=[.!?])\s+', parent2.text)

        if len(sentences1) < 2 or len(sentences2) < 2:
            # Word-level crossover
            words1 = parent1.text.split()
            words2 = parent2.text.split()
            cut1 = self._rng.randint(0, len(words1))
            cut2 = self._rng.randint(0, len(words2))
            child_text = " ".join(words1[:cut1] + words2[cut2:])
        else:
            cut1 = self._rng.randint(1, len(sentences1))
            cut2 = self._rng.randint(0, len(sentences2))
            child_text = " ".join(sentences1[:cut1] + sentences2[cut2:])

        atype = attack_type or parent1.attack_type
        gene = PromptGene(
            prompt_id=self._gen_id(child_text),
            text=child_text.strip(),
            attack_type=atype,
            source="crossover",
            parent_ids=[parent1.prompt_id, parent2.prompt_id],
            generation=self._generation,
            mutation_type="crossover",
        )
        return gene

    def _mutate_gene(
        self,
        parent: PromptGene,
        preferred_strategies: Optional[List[str]] = None,
    ) -> PromptGene:
        """Apply a mutation from PayloadMutator."""
        parent_prompt = AdversarialPrompt(
            text=parent.text,
            attack_type=parent.attack_type,
            category="",
            severity="high",
            source=parent.source,
            tags=[],
        )
        strategies = preferred_strategies or self._mutator.available_strategies
        # Weighted towards preferred strategies
        if preferred_strategies:
            strategy_pool = preferred_strategies * 3 + self._mutator.available_strategies
        else:
            strategy_pool = self._mutator.available_strategies

        mutations = self._mutator.mutate(parent_prompt, strategies=strategies, count=1)

        if mutations:
            m = mutations[0]
            child_text = m.text
            mut_type = m.mutation_type
        else:
            # Fallback: minor word-level change
            words = parent.text.split()
            if len(words) > 2:
                idx = self._rng.randint(0, len(words) - 1)
                words[idx] = words[idx].upper()
            child_text = " ".join(words)
            mut_type = "case_variation"

        return PromptGene(
            prompt_id=self._gen_id(child_text),
            text=child_text.strip(),
            attack_type=parent.attack_type,
            source="mutation",
            parent_ids=[parent.prompt_id],
            generation=self._generation,
            mutation_type=mut_type,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _to_gene(
        self, prompt: AdversarialPrompt, source: str, generation: int
    ) -> PromptGene:
        return PromptGene(
            prompt_id=self._gen_id(prompt.text),
            text=prompt.text,
            attack_type=prompt.attack_type,
            source=source,
            parent_ids=[],
            generation=generation,
            mutation_type="",
        )

    @staticmethod
    def _gen_id(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:16]
