from typing import Optional


class DailyActionPlanQueries:

    @staticmethod
    def vulnerability_detector_filter() -> dict:
        return {"term": {"rule.groups": "vulnerability-detector"}}

    @staticmethod
    def active_status_filter() -> dict:
        return {"term": {"data.vulnerability.status": "Active"}}

    @staticmethod
    def cve_agent_details_agg() -> dict:
        return {
            "details": {
                "top_hits": {
                    "size": 1,
                    "_source": [
                        "agent.name",
                        "data.vulnerability.severity",
                        "data.vulnerability.cvss.cvss3.base_score",
                        "data.vulnerability.cvss.cvss2.base_score",
                        "data.vulnerability.package.condition",
                        "data.vulnerability.package.name",
                        "data.vulnerability.scanner.source",
                        "data.vulnerability.title",
                    ],
                }
            }
        }

    @classmethod
    def vulnerabilities_by_agent_composite_agg(
        cls, after_key: Optional[dict] = None, page_size: int = 1000
    ) -> dict:
        composite: dict = {
            "size": page_size,
            "sources": [
                {"cve": {"terms": {"field": "data.vulnerability.cve"}}},
                {"agent": {"terms": {"field": "agent.id"}}},
            ],
        }
        if after_key:
            composite["after"] = after_key

        return {
            "vulnerabilities_by_agent": {
                "composite": composite,
                "aggs": cls.cve_agent_details_agg(),
            }
        }

    @classmethod
    def vulnerabilities_by_agent(
        cls,
        after_key: Optional[dict] = None,
        page_size: int = 1000,
        timeout: str = "30s",
    ) -> dict:
        """
        Pas de filtre de date : l'index ciblé (résolu en amont via date_utils)
        porte déjà la sémantique temporelle. rule.groups reste nécessaire car
        wazuh-alerts-4.x-* mélange tous les types d'événements.
        """
        return {
            "size": 0,
            "track_total_hits": True,
            "timeout": timeout,
            "query": {
                "bool": {
                    "filter": [
                        cls.vulnerability_detector_filter(),
                        cls.active_status_filter(),
                    ],
                }
            },
            "aggs": cls.vulnerabilities_by_agent_composite_agg(
                after_key=after_key, page_size=page_size
            ),
        }