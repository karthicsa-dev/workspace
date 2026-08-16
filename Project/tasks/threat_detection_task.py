"""
Threat Detection task.

Implement build_threat_detection_task(agent, state) and the DetectionAssessment output schema.
The task instructs the agent to detect threats and judge a threat_severity_score.
See the problem description for the output fields and the schema.
"""
from typing import Any, Dict, List

from crewai import Agent, task
from pydantic import BaseModel, Field

from core.config import SEVERITY_LEVELS, THREAT_CATEGORIES

class ThreatFinding(BaseModel):
    threat: str = Field(
        ...,
        description = (
            "Name or concise description of the identified threat."
        ),
    )

    category: str = Field(
        ...,
        description = (
            "Threat category. Prefer one of the configured threat categories when applicable."
        ),
    )

    severity: str = Field(
        ...,
        description = (
            "LLM-assessed severity classification of the threat, such as Informational, High, Medium or Low."
        ),
    )

    affected_systems: List[str] = Field(
        default_factory=list,
        description = (
            "Systems or assets that appear to be affected based on the available detection evidence."
        ),
    )

class DetectionAssessmentAssessment(BaseModel):
    threat_data: List[ThreatFinding] = Field(
        default_factory = list,
        description = (
            "Threats detected from the available SIEM and network IDS evidence."
        ),
    )

    analyzed: bool = Field(
        ...,
        description = (
            "True when available threat intelligence and endpoint telemetry have been successfully analyzed."
        ),
    )

    critical_threats: int = Field(
        ...,
        ge = 0,
        description = (
            "Number of threats that the LLM independently judges to be critical based on the complete evidence. This MUST be a reasoned LLM judgement and MUST NOT be calculated using a hard-coded formula or simple severity-field count."
        ),
    )

def build_threat_analysis_task(agent: Agent, state: Dict[str, Any]) -> Task:
    organization = state.get("organization", "UNKNOWN")

    description = f""" 
    
    """