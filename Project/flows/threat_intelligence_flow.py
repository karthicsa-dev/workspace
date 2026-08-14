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

            self.state["intel"]["threat_"]