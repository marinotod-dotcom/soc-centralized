from datetime import datetime
from src.models.enums.kpi_pattern_enum import KPIPattern


class FimQueries:

    FIM_RULE_IDS = [
        "550", "553", "554", "555", "556",
        "594", "597", "598",
        "750", "751", "752",
    ]

    _UNIQUE_PATH_SCRIPT = {
        "lang": "painless",
        "source": """
            String agent = doc.containsKey('agent.id') && doc['agent.id'].size() > 0
                ? doc['agent.id'].value : '';
            String path = doc.containsKey('syscheck.path') && doc['syscheck.path'].size() > 0
                ? doc['syscheck.path'].value : '';
            return agent + '|' + path;
        """
    }

    _UNIQUE_EVENT_SCRIPT = {
        "lang": "painless",
        "source": """
            String agent = doc.containsKey('agent.id') && doc['agent.id'].size() > 0
                ? doc['agent.id'].value : '';
            String path = doc.containsKey('syscheck.path') && doc['syscheck.path'].size() > 0
                ? doc['syscheck.path'].value : '';
            String evt = doc.containsKey('syscheck.event') && doc['syscheck.event'].size() > 0
                ? doc['syscheck.event'].value : '';
            return agent + '|' + path + '|' + evt;
        """
    }

    @staticmethod
    def date_range(date_from: datetime, date_to: datetime) -> dict:
        return {
            "range": {
                "@timestamp": {
                    "gte": date_from.strftime("%Y-%m-%dT%H:%M:%S"),
                    "lte": date_to.strftime("%Y-%m-%dT%H:%M:%S"),
                    "format": "strict_date_optional_time",
                }
            }
        }

    @classmethod
    def fim_filter(cls) -> list:
        return [
            {
                "bool": {
                    "should": [
                        {"term": {"decoder.name": "syscheck"}},
                        {"match": {"rule.groups": "syscheck"}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            {"exists": {"field": "syscheck.event"}},
            {"terms": {"rule.id": cls.FIM_RULE_IDS}},
        ]

    @classmethod
    def bool_query(cls, date_from: datetime, date_to: datetime) -> dict:
        return {
            "bool": {"must": cls.fim_filter() + [cls.date_range(date_from, date_to)]}
        }

    @classmethod
    def _path_should(cls, patterns: list) -> list:
        return [{"wildcard": {"syscheck.path": p}} for p in patterns]

    @classmethod
    def total_event_count(cls, date_from: datetime, date_to: datetime) -> dict:
        return {
            "size": 0,
            "track_total_hits": True,
            "query": cls.bool_query(date_from, date_to),
            "aggs": {
                "unique_events": {
                    "cardinality": {
                        "script":              cls._UNIQUE_EVENT_SCRIPT,
                        "precision_threshold": 40000,
                    }
                }
            },
        }

    @classmethod
    def event_type_breakdown(cls, date_from: datetime, date_to: datetime) -> dict:
        return {
            "size": 0,
            "track_total_hits": False,
            "query": cls.bool_query(date_from, date_to),
            "aggs": {
                "added": {
                    "filter": {"term": {"syscheck.event": "added"}},
                    "aggs": {
                        "unique": {
                            "cardinality": {
                                "script":              cls._UNIQUE_PATH_SCRIPT,
                                "precision_threshold": 40000,
                            }
                        }
                    },
                },
                "deleted": {
                    "filter": {"term": {"syscheck.event": "deleted"}},
                    "aggs": {
                        "unique": {
                            "cardinality": {
                                "script":              cls._UNIQUE_PATH_SCRIPT,
                                "precision_threshold": 40000,
                            }
                        }
                    },
                },
                "modified": {
                    "filter": {"term": {"syscheck.event": "modified"}},
                    "aggs": {
                        "unique": {
                            "cardinality": {
                                "script":              cls._UNIQUE_PATH_SCRIPT,
                                "precision_threshold": 40000,
                            }
                        },
                        "avec_hash": {
                            "filter": {
                                "bool": {
                                    "should": [
                                        {"exists": {"field": "syscheck.md5_after"}},
                                        {"exists": {"field": "syscheck.sha1_after"}},
                                        {"exists": {"field": "syscheck.sha256_after"}},
                                    ],
                                    "minimum_should_match": 1,
                                }
                            },
                            "aggs": {
                                "unique": {
                                    "cardinality": {
                                        "script":              cls._UNIQUE_PATH_SCRIPT,
                                        "precision_threshold": 40000,
                                    }
                                }
                            },
                        },
                    },
                },
            },
        }

    @classmethod
    def alert_levels_breakdown(cls, date_from: datetime, date_to: datetime) -> dict:
        return {
            "size": 0,
            "track_total_hits": False,
            "query": cls.bool_query(date_from, date_to),
            "aggs": {
                "critical": {
                    "filter": {
                        "bool": {
                            "should": [
                                {"range": {"rule.level": {"gte": 10}}},
                                *cls._path_should(KPIPattern.CRITICAL_PATTERNS_LINUX.value),
                                *cls._path_should(KPIPattern.CRITICAL_PATTERNS_WINDOWS.value),
                            ],
                            "minimum_should_match": 1,
                        }
                    }
                },
                "high": {
                    "filter": {
                        "bool": {
                            "should": cls._path_should(KPIPattern.HIGH_PATTERNS.value),
                            "minimum_should_match": 1,
                        }
                    }
                },
            },
        }

    @classmethod
    def mode_breakdown(cls, date_from: datetime, date_to: datetime) -> dict:
        return {
            "size": 0,
            "track_total_hits": False,
            "query": cls.bool_query(date_from, date_to),
            "aggs": {"par_mode": {"terms": {"field": "syscheck.mode", "size": 10}}},
        }