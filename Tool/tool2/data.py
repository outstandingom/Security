from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Tuple

class SecurityTester(ABC):
    """Base class for all security testing modules"""
    def __init__(self, target_url: str, params: Dict[str, Any], headers: Optional[Dict] = None):
        self.target_url = target_url
        self.params = params
        self.headers = headers or {}
        self.vulnerabilities: List[Dict] = []

    @abstractmethod
    def test(self) -> List[Dict]:
        pass


class DatabaseTester(SecurityTester):
    """
    Unified tester for both SQL and NoSQL injection vulnerabilities.
    Can detect database type and run appropriate tests.
    """
    
    def __init__(self, target_url: str, params: Dict[str, Any], method: str = "GET", **kwargs):
        super().__init__(target_url, params, **kwargs)
        self.method = method.upper()
        self.db_type: Optional[str] = None  # 'sql', 'mongodb', 'couchdb', etc.
        self.detection_confidence: float = 0.0

    def detect_database_type(self) -> Tuple[Optional[str], float]:
        """
        Attempt to determine whether target uses SQL or NoSQL
        Returns (database_type, confidence)
        """
        # Many real implementations use multiple techniques:
        # 1. Error message analysis
        # 2. Timing differences
        # 3. Payload-specific responses
        # 4. Response fingerprinting
        
        sql_indicators = [
            ("syntax error", 0.7),
            ("mysql_fetch", 0.85),
            ("SQLSTATE", 0.8),
            ("near", 0.6),  # often appears in postgres/sqlite errors
            ("ORA-", 0.9),   # Oracle
            ("Microsoft OLE DB Provider", 0.85)
        ]
        
        nosql_indicators = [
            ("MongoError", 0.8),
            ("unexpected token", 0.65),  # common JS parsing error in NoSQL
            ("code: 102", 0.75),        # MongoDB error code style
            ("EJSON", 0.7),
            ("BSON", 0.7)
        ]
        
        confidence_sql = 0.0
        confidence_nosql = 0.0
        
        # Here you would typically:
        # 1. Send known error-inducing payloads for each type
        # 2. Analyze response codes, bodies, headers, timing
        
        # Simplified dummy implementation:
        for indicator, conf in sql_indicators:
            if self._probe_with_payload("' OR 1=1 --", indicator[0]):
                confidence_sql = max(confidence_sql, conf)
                
        for indicator, conf in nosql_indicators:
            if self._probe_with_payload('{"$ne": null}', indicator[0]):
                confidence_nosql = max(confidence_nosql, conf)
        
        if confidence_sql > confidence_nosql and confidence_sql > 0.55:
            return "sql", confidence_sql
        elif confidence_nosql > confidence_sql and confidence_nosql > 0.55:
            return "nosql", confidence_nosql
        else:
            return None, max(confidence_sql, confidence_nosql)

    def detect_nosql(self) -> bool:
        """Quick check if we should bother with NoSQL tests"""
        if self.db_type is None:
            self.db_type, self.detection_confidence = self.detect_database_type()
        return self.db_type == "nosql" or self.detection_confidence > 0.65

    def test_all_injections(self, aggressive: bool = False) -> List[Dict]:
        """Main entry point - test everything we can"""
        results = []
        
        # Always try SQL tests (many apps have both!)
        sql_results = self.test_sql_injection(aggressive=aggressive)
        results.extend(sql_results)
        
        # Try NoSQL if it seems relevant
        if self.detect_nosql() or aggressive:
            nosql_results = self.test_nosql_injection(aggressive=aggressive)
            results.extend(nosql_results)
            
        self.vulnerabilities = results
        return results

    def test_sql_injection(self, aggressive: bool = False) -> List[Dict]:
        """Your existing SQL injection testing logic"""
        # ... your original SQL test implementation ...
        return [{"type": "sql", "payload": "...", "vulnerable": False, ...}]

    def test_nosql_injection(self, aggressive: bool = False) -> List[Dict]:
        """
        NoSQL injection tests (MongoDB, CouchDB, etc.)
        Most common target is MongoDB right now
        """
        payloads = [
            # Classic auth bypass attempts
            {'username': {'$ne': None}, 'password': {'$ne': None}},
            {'username': {'$eq': 'admin'}, 'password': ''},
            {'$or': [{'username': 'admin'}, {'username': 'guest'}]},
            {'username': 'admin', 'password': {'$regex': '^a'}},
            
            # JavaScript injection style (older Node+Mongo)
            {'username': 'admin', 'password': ';return true//'},
            
            # Type confusion / operator abuse
            {'age': {'$gt': '18'}},
            {'score': {'$gt': -999999}},
        ]
        
        if aggressive:
            payloads.extend([
                {'$where': 'this.username == "admin"'},
                {'username': {'$where': 'return true'}},
                {'__proto__': {'admin': True}},
            ])
            
        results = []
        
        for payload in payloads:
            vulnerable, evidence = self._try_nosql_payload(payload)
            if vulnerable:
                results.append({
                    "type": "nosql",
                    "payload": str(payload),
                    "description": "Potential NoSQL injection",
                    "confidence": "high" if "auth bypass" in evidence else "medium",
                    "evidence": evidence[:200],
                    "risk": "HIGH"
                })
                
        return results

    def _try_nosql_payload(self, payload: Any) -> Tuple[bool, str]:
        """Send payload and analyze response - implement according to your framework"""
        # This is where you would:
        # 1. Serialize payload appropriately (JSON, form data, etc.)
        # 2. Send request
        # 3. Check for anomalies (status code, response time, content change, error messages)
        return False, ""

    def _probe_with_payload(self, payload: str, error_signature: str) -> bool:
        """Helper for DB type detection"""
        # Implement actual request + response checking
        return False

    def report(self) -> str:
        """Generate human-readable report"""
        if not self.vulnerabilities:
            return "No database injection vulnerabilities detected."
            
        lines = [f"Found {len(self.vulnerabilities)} potential database injection issues:"]
        for vuln in self.vulnerabilities:
            lines.append(f"• {vuln['type'].upper()} - {vuln['payload']}")
            lines.append(f"  Risk: {vuln['risk']}")
            lines.append(f"  Evidence: {vuln.get('evidence', 'N/A')[:120]}...")
            lines.append("")
        return "\n".join(lines)
