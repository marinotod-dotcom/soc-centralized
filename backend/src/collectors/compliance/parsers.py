class ComplianceParsers:

    @staticmethod
    def total_hits(response: dict) -> int:
        return response.get("hits", {}).get("total", {}).get("value", 0)

    @staticmethod
    def agg(response: dict, name: str) -> dict:
        return response.get("aggregations", {}).get(name, {})

    @staticmethod
    def agg_value(response: dict, name: str):
        return ComplianceParsers.agg(response, name).get("value")

    @staticmethod
    def bucket_count(response: dict, name: str) -> int:
        return (
            ComplianceParsers.agg(response, name)
            .get("count", {})
            .get("value", 0)
        )

    @classmethod
    def compliance_stats(cls, response: dict) -> dict:
        return {
            "total": cls.agg_value(response, "total") or 0,
            "critique": cls.bucket_count(response, "critique"),
            "eleve": cls.bucket_count(response, "eleve"),
            "moyen": cls.bucket_count(response, "moyen"),
            "faible": cls.bucket_count(response, "faible"),
        }

    @classmethod
    def rgpd(cls, response: dict) -> dict:
        return cls.compliance_stats(response)

    @classmethod
    def hipaa(cls, response: dict) -> dict:
        return cls.compliance_stats(response)
