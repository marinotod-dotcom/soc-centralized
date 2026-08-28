from datetime import datetime

class LogQueries:

    @staticmethod
    def date_range(date_from: datetime, date_to: datetime) -> dict:
        return {
            "range": {
                "timestamp": {
                    "gte": date_from.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "lte": date_to.strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
            }
        }

    @staticmethod
    def critical_level_filter() -> dict:
        return {"range": {"rule.level": {"gte": 12}}}

    @staticmethod
    def unique_agent_rule_agg() -> dict:
        return {
            "total_uniques": {
                "cardinality": {
                    "script": {
                        "source": "doc['agent.name'].value + '|' + doc['rule.id'].value"
                    }
                }
            }
        }

    @staticmethod
    def agent_summary_url() -> str:
        return "/agents/summary"

    @staticmethod
    def never_connected_agents_url() -> str:
        return (
            "/agents"
            "?status=disconnected"
            "&older_than=7d"
            "&select=id"
            "&limit=1"
            "&offset=0"
        )

    @classmethod
    def confirmed_incidents(cls, date_from: datetime, date_to: datetime) -> dict:
        return {
            "size": 0,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "must": [
                        cls.critical_level_filter(),
                        cls.date_range(date_from, date_to),
                    ],
                }
            },
            "aggs": cls.unique_agent_rule_agg(),
        }
