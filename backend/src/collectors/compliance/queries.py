from datetime import datetime


class ComplianceQueries:
    """Requêtes de conformité (GDPR / HIPAA)."""

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

    @staticmethod
    def compliance_filter(field: str) -> list:
        return [
            {
                "exists": {
                    "field": field,
                }
            }
        ]

    @classmethod
    def bool_query(
        cls,
        field: str,
        date_from: datetime,
        date_to: datetime,
    ) -> dict:
        return {
            "bool": {
                "must": cls.compliance_filter(field)
                + [cls.date_range(date_from, date_to)]
            }
        }


    @staticmethod
    def level_bucket(min_level: int, max_level: int | None = None) -> dict:
        range_query = {
            "from": min_level,
            "include_lower": True,
            "include_upper": True,
        }

        if max_level is not None:
            range_query["to"] = max_level

        return {
            "filter": {
                "range": {
                    "rule.level": range_query
                }
            },
            "aggs": {
                "count": {
                    "value_count": {
                        "field": "agent.name"
                    }
                }
            },
        }

    @classmethod
    def compliance_stats(
        cls,
        date_from: datetime,
        date_to: datetime,
        field: str,
        high_range: tuple[int, int | None],
        medium_range: tuple[int, int],
        low_range: tuple[int, int],
    ) -> dict:
        return {
            "size": 0,
            "track_total_hits": True,
            "query": cls.bool_query(field, date_from, date_to),
            "aggs": {
                "total": {
                    "value_count": {
                        "field": "agent.name"
                    }
                },
                "critique": cls.level_bucket(*high_range),
                "eleve": cls.level_bucket(*medium_range),
                "moyen": cls.level_bucket(*low_range),
                "faible": cls.level_bucket(3, 4),
            },
        }


    @classmethod
    def rgpd(
        cls,
        date_from: datetime,
        date_to: datetime,
    ) -> dict:
        return cls.compliance_stats(
            date_from=date_from,
            date_to=date_to,
            field="rule.gdpr",
            high_range=(13, None),
            medium_range=(8, 12),
            low_range=(5, 7),
        )


    @classmethod
    def hipaa(
        cls,
        date_from: datetime,
        date_to: datetime,
    ) -> dict:
        return cls.compliance_stats(
            date_from=date_from,
            date_to=date_to,
            field="rule.hipaa",
            high_range=(13, None),
            medium_range=(9, 12),
            low_range=(5, 8),
        )
