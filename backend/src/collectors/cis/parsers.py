class CisBenchmarkParsers:

    @staticmethod
    def total_hits(response: dict) -> int:
        return response.get("hits", {}).get("total", {}).get("value", 0)

    @staticmethod
    def agg_value(response: dict, agg_name: str) -> float | None:
        return response.get("aggregations", {}).get(agg_name, {}).get("value")

    @staticmethod
    def buckets(response: dict, agg_name: str) -> list:
        return response.get("aggregations", {}).get(agg_name, {}).get("buckets", [])

    # ─── Requete A ────────────────────────────────────────────

    @classmethod
    def score_global(cls, response: dict) -> dict:
        raw_avg = cls.agg_value(response, "score_moyen")
        raw_min = cls.agg_value(response, "score_min")
        raw_max = cls.agg_value(response, "score_max")
        return {
            "score_moyen": round(raw_avg, 2) if raw_avg is not None else None,
            "score_min": round(raw_min, 2) if raw_min is not None else None,
            "score_max": round(raw_max, 2) if raw_max is not None else None,
        }

    # ─── Requete B ────────────────────────────────────────────

    @classmethod
    def score_by_policy(cls, response: dict) -> list:
        return [
            {
                "policy": b["key"],
                "score_moyen": round(b.get("score", {}).get("value") or 0, 2),
                "count": b["doc_count"],
            }
            for b in cls.buckets(response, "score_par_policy")
        ]

    @classmethod
    def scanned_agents(cls, response: dict) -> int:
        return cls.agg_value(response, "agents_couverts")
