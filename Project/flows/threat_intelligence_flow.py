"""
The CrewAI Flow for threat intelligence.

Implement ThreatIntelligenceFlow: a CrewAI Flow whose steps are wired with @start, @listen and a
@router (rejoining the mode branches with or_). The router reads the analyst's own judgement.
See the problem description for the step methods, the routing labels, and the mode/rejoin structure.
"""
import time
from typing import Any, Dict

from crewai.flow.flow import Flow, listen, or_, router, start

from agents.incident_response_agent import IncidentResponseAgent
from agents.security_recommendation_agent import SecurityRecommendationAgent
from agents.threat_analysis_agent import ThreatAnalysisAgent
from agents.threat_detection_agent import ThreatDetectionAgent
from core.config import (
    ROUTE_PRIORITY,
    ROUTE_STANDARD,
    STATUS_COMPLETED,
    STATUS_REVIEW,
    config,
)
from core.state import (
    add_agent_result,
    add_error,
    create_intel_state,
    finalize_status,
)
from utils.database import record_intel

class ThreatIntelligenceFlow(Flow):
    def __init__(self) -> None:
        super().__init__()

        self.detector = ThreatDetectionAgent()
        self.analyst =  ThreatAnalysisAgent()
        self.responder = IncidentResponseAgent()
        self.advisor = SecurityRecommendationAgent()

    @start()
    async def detect_threats(self, organization: str) -> Dict[str, Any]:
        intel = create_intel_state(
            {
                "organization": organization,
            }
        )

        self.state["intel"] = intel
        self.state["workflow_started_at"] = time.perf_counter()

        step_started = time.perf_counter()

        try:
            result = await self.detector.execute_async(
                self.state["intel"]
            )

            add_agent_result(
                self.state["intel"],
                self.detector.agent_name,
                result,
            )

            self.state["intel"]["threat_data"] = result.get(
                "threat_data",
                {},
            )
            self.state["intel"]["threat_severity_score"] = result.get(
                "threat_severity_score",
                0.0,
            )
            self.state["intel"]["compromised_systems"] = result.get(
                "compromised_systems",
                0,
            )
            self.state["intel"]["detected"] = result.get(
                "detected",
                False,
            )

            if result.get("status") == "error":
                add_error(
                    self.state["intel"],
                    result.get("error", "Threat detection failed."),
                    self.detector.agent_name,
                )

        except Exception as exc:
            add_error(
                self.state["intel"],
                str(exc),
                self.detector.agent_name,
            )
        
        self.state["intel"]["metrics"]["detection_seconds"] = round(
            time.perf_counter() - step_started,
            3,
        )

        return self.state["intel"]

    @listen(detect_threats)
    async def analyze_threats(self, intel: Dict[str, Any]) -> Dict[str, Any]:
        step_started = time.perf_counter()

        try:
            result = await self.analyst.execute_async(
                self.state["intel"]
            )

            add_agent_result(
                self.state["intel"],
                self.analyst.agent_name,
                result,
            )

            self.state["intel"]["threat_analysis"] = result.get(
                "threat_analysis",
                {},
            )
            self.state["intel"]["critical_threats"] = result.get(
                "critical_threats",
                0,
            )
            self.state["intel"]["analyzed"] = result.get(
                "analyzed",
                False,
            )

            if result.get("status") == "error":
                add_error(
                    self.state["intel"],
                    result.get("error", "Threat analysis failed."),
                    self.analyst.agent_name,
                )

        except Exception as exc:
            add_error(
                self.state["intel"],
                str(exc),
                self.analyst.agent_name,
            )
        
        self.state["intel"]["metrics"]["analysis_seconds"] = round(
            time.perf_counter() - step_started,
            3,
        )

        return self.state["intel"]

    @router(analyze_threats)
    def route_by_criticality(self, intel: Dict[str, Any]) -> Dict[str, Any]:
        critical_threats = intel.get("critical_threats", 0)

        if critical_threats >= config.critical_threat_floor:
            return ROUTE_PRIORITY
        
        return ROUTE_STANDARD

    @listen
    