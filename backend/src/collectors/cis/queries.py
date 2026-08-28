from datetime import datetime


class CisBenchmarkQueries:

    @staticmethod
    def sca_filter() -> list:
        """Filtre de base : evenements SCA uniquement."""
        return [
            {"term": {"rule.groups": "sca"}},
        ]

    @staticmethod
    def sca_failed_filter() -> list:
        """Filtre checks SCA en echec avec un ID de check present."""
        return [
            {"term": {"rule.groups": "sca"}},
            {"term": {"data.sca.check.result": "failed"}},
            {"exists": {"field": "data.sca.check.id"}},
        ]

    @staticmethod
    def sca_summary_filter() -> list:
        """Filtre evenements de type 'summary' (scores consolides par policy)."""
        return [
            {"term": {"rule.groups": "sca"}},
            {"term": {"data.sca.type": "summary"}},
        ]

    @staticmethod
    def date_range(date_from: datetime, date_to: datetime) -> dict:
        return {
            "range": {
                "timestamp": {
                    "gte": date_from.strftime("%Y-%m-%dT%H:%M:%S"),
                    "lte": date_to.strftime("%Y-%m-%dT%H:%M:%S"),
                }
            }
        }

    @classmethod
    def bool_query(cls, date_from: datetime, date_to: datetime) -> dict:
        return {
            "bool": {"must": cls.sca_filter() + [cls.date_range(date_from, date_to)]}
        }

    @classmethod
    def failed_bool_query(cls, date_from: datetime, date_to: datetime) -> dict:
        return {
            "bool": {
                "must": cls.sca_failed_filter() + [cls.date_range(date_from, date_to)]
            }
        }

    @classmethod
    def summary_bool_query(cls, date_from: datetime, date_to: datetime) -> dict:
        return {
            "bool": {
                "must": cls.sca_summary_filter() + [cls.date_range(date_from, date_to)]
            }
        }

    # ─── Corps de requetes (A–F) ──────────────────────────────────────────────

    @classmethod
    def score_global(cls, date_from: datetime, date_to: datetime) -> dict:
        """Requete D – Score SCA global : moyenne, min, max."""
        return {
            "size": 0,
            "track_total_hits": True,
            "query": cls.summary_bool_query(date_from, date_to),
            "aggs": {
                "score_moyen": {"avg": {"field": "data.sca.score"}},
                "score_min": {"min": {"field": "data.sca.score"}},
                "score_max": {"max": {"field": "data.sca.score"}},
            },
        }

    @classmethod
    def score_by_policy(
        cls, date_from: datetime, date_to: datetime, top_n: int = 10
    ) -> dict:
        """Requete E – Score moyen par politique CIS."""
        return {
            "size": 0,
            "track_total_hits": True,
            "query": cls.summary_bool_query(date_from, date_to),
            "aggs": {
                "score_par_policy": {
                    "terms": {
                        "field": "data.sca.policy",
                        "size": top_n,
                        "order": [{"_count": "desc"}, {"_key": "asc"}],
                    },
                    "aggs": {"score": {"avg": {"field": "data.sca.score"}}},
                }
            },
        }

    @classmethod
    def scanned_agents(cls, date_from: datetime, date_to: datetime) -> dict:
        """Agents distincts ayant produit un resultat SCA + date du dernier scan par agent."""
        return {
            "size": 0,
            "track_total_hits": True,
            "query": cls.summary_bool_query(date_from, date_to),
            "aggs": {
                "agents_couverts": {"cardinality": {"field": "agent.id"}},
            },
        }
