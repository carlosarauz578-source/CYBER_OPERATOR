"""
Result Aggregator Module
Aggregates and correlates results from multiple sources
"""

from typing import Dict, List, Any, Set
from datetime import datetime
from collections import defaultdict
import json
import copy


class ResultAggregator:
    """Aggregates and correlates results from multiple sources"""
    
    def __init__(self):
        self.raw_results: List[Dict] = []
        self.aggregated_data: Dict = {}
    
    def add_results(self, results: List[Any]) -> None:
        """
        Add query results to aggregation.
        
        Args:
            results: List of QueryResult objects
        """
        self.raw_results = []
        for result in results:
            if isinstance(result, dict):
                self.raw_results.append(copy.deepcopy(result))
            else:
                self.raw_results.append(
                    copy.deepcopy(vars(result)) if hasattr(result, '__dict__') else {}
                )
    
    def aggregate(self, target: str, results: List[Any] = None,
                  query_id: str = None) -> Dict:
        """
        Aggregate all results into a comprehensive report.
        
        Args:
            target: The search target
            
        Returns:
            Aggregated results dictionary
        """
        if results is not None:
            self.add_results(results)
        self.aggregated_data = {
            "query_id": query_id,
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "summary": self._generate_summary(),
            "findings": self._extract_findings(),
            "correlations": self._correlate_findings(),
            "sources": self._organize_by_source(),
            "risk_assessment": self._assess_risk()
        }
        
        return self.aggregated_data
    
    def _generate_summary(self) -> Dict:
        """Generate summary statistics"""
        total = len(self.raw_results)
        successful = len([r for r in self.raw_results if r.get("success", False)])
        
        return {
            "total_sources_queried": total,
            "successful_queries": successful,
            "failed_queries": total - successful,
            "success_rate": (successful / total * 100) if total > 0 else 0
        }
    
    def _extract_findings(self) -> List[Dict]:
        """Extract significant findings from results"""
        findings = []
        
        for result in self.raw_results:
            if not result.get("success"):
                continue
            
            data = self.normalize(result.get("data", {}))
            if not data:
                continue
            
            # Extract key findings
            source_name = result.get("source_name", "Unknown")
            
            # Parse different types of data
            if isinstance(data, dict):
                for key, value in data.items():
                    if value and key not in [
                        "source", "target", "status", "success", "error", "raw_data"
                    ]:
                        finding = {
                            "source": source_name,
                            "category": key,
                            "data": value,
                            "timestamp": result.get("timestamp", "")
                        }
                        if finding not in findings:
                            findings.append(finding)
        
        return findings
    
    def _correlate_findings(self) -> Dict:
        """Correlate findings across multiple sources"""
        correlations = {
            "common_findings": defaultdict(list),
            "conflicts": [],
            "validations": defaultdict(int)
        }
        
        # Group by finding type across sources
        finding_map = defaultdict(list)
        
        for finding in self._extract_findings():
            key = f"{finding['category']}:{str(finding['data'])[:50]}"
            finding_map[key].append(finding['source'])
        
        # Identify common findings (mentioned by multiple sources)
        for key, sources in finding_map.items():
            if len(sources) > 1:
                correlations["common_findings"][key] = sources
                correlations["validations"][key] = len(sources)
        
        return dict(correlations)
    
    def _organize_by_source(self) -> Dict:
        """Organize results by source"""
        by_source = defaultdict(lambda: {
            "success": False,
            "data": {},
            "normalized_data": {},
            "error": None,
            "execution_time": 0,
            "availability_status": "unknown",
            "execution_status": "unknown",
            "cached": False,
        })
        
        for result in self.raw_results:
            source_id = result.get("source_id", "unknown")
            by_source[source_id] = {
                "source_name": result.get("source_name", source_id),
                "success": result.get("success", False),
                "data": result.get("data", {}),
                "normalized_data": self.normalize(result.get("data", {})),
                "error": result.get("error"),
                "execution_time": result.get("execution_time", 0),
                "availability_status": result.get("availability_status", "unknown"),
                "execution_status": result.get("execution_status", "unknown"),
                "cached": result.get("cached", False),
                "persistence_error": result.get("persistence_error"),
            }
        
        return dict(by_source)

    @classmethod
    def normalize(cls, value):
        """Return a deduplicated JSON-safe view without modifying source data."""
        if isinstance(value, dict):
            return {key: cls.normalize(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            normalized = []
            seen = set()
            for item in value:
                clean_item = cls.normalize(item)
                key = json.dumps(clean_item, sort_keys=True, default=str)
                if key not in seen:
                    seen.add(key)
                    normalized.append(clean_item)
            return normalized
        if isinstance(value, str):
            return value.strip()
        return value
    
    def _assess_risk(self) -> Dict:
        """Assess risk based on findings"""
        risk_assessment = {
            "level": "LOW",
            "indicators": [],
            "score": 0,
            "interpretation": "Heuristic indicators only; not a vulnerability confirmation."
        }
        
        findings = self._extract_findings()
        
        # Simple risk scoring based on findings
        risk_keywords = {
            "malware": 3,
            "malicious": 3,
            "abuse": 2,
            "blocked": 2,
            "threat": 2,
            "vulnerable": 2,
            "compromised": 3,
            "spam": 1,
            "phishing": 3
        }
        
        for finding in findings:
            data_str = str(finding.get("data", "")).lower()
            for keyword, risk_value in risk_keywords.items():
                if keyword in data_str:
                    risk_assessment["score"] += risk_value
                    risk_assessment["indicators"].append(
                        f"{keyword} detected in {finding['source']}"
                    )
        
        # Determine risk level
        if risk_assessment["score"] >= 6:
            risk_assessment["level"] = "HIGH"
        elif risk_assessment["score"] >= 3:
            risk_assessment["level"] = "MEDIUM"
        else:
            risk_assessment["level"] = "LOW"
        
        return risk_assessment
    
    def get_aggregated_data(self) -> Dict:
        """Get aggregated results"""
        return self.aggregated_data
    
    def export_json(self) -> str:
        """Export aggregated results as JSON"""
        return json.dumps(self.aggregated_data, indent=2, default=str)
    
    def export_markdown(self) -> str:
        """Export aggregated results as Markdown"""
        md = f"# Intelligence Report\n\n"
        md += f"**Target:** {self.aggregated_data.get('target', 'Unknown')}\n"
        md += f"**Date:** {self.aggregated_data.get('timestamp', 'Unknown')}\n\n"
        
        # Summary
        summary = self.aggregated_data.get('summary', {})
        md += f"## Summary\n\n"
        md += f"- Total Sources: {summary.get('total_sources_queried', 0)}\n"
        md += f"- Successful: {summary.get('successful_queries', 0)}\n"
        md += f"- Success Rate: {summary.get('success_rate', 0):.1f}%\n\n"
        
        # Risk Assessment
        risk = self.aggregated_data.get('risk_assessment', {})
        md += f"## Risk Assessment\n\n"
        md += f"**Level:** {risk.get('level', 'UNKNOWN')}\n"
        md += f"**Score:** {risk.get('score', 0)}\n\n"
        
        if risk.get('indicators'):
            md += "**Indicators:**\n"
            for indicator in risk.get('indicators', []):
                md += f"- {indicator}\n"
            md += "\n"
        
        # Correlations
        correlations = self.aggregated_data.get('correlations', {})
        if correlations.get('common_findings'):
            md += f"## Correlated Findings\n\n"
            for finding, sources in correlations.get('common_findings', {}).items():
                md += f"- **{finding}** (mentioned by {len(sources)} sources)\n"
            md += "\n"
        
        return md
