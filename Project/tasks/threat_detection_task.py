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
    You are the threat detection specialist for:

    Organization: {organization}

    Your responsibility is to identify meaningful cybersecurity threats from the organization's available SIEM and network intrusion-detection evidence. 

    SHARED INTELLIGENCE RECORD: 
    {state}

    You MUST use both of your deterministic data sources before completing the assessment:

    1. SIEM Event Monitor
        - Review the number and severity of security events.
        - Review alerts raised.
        - Review severity distribution.
        - Review event sources.
        - Review failed authentication attempts.
        - Use this information to identify suspicious or potentially malicious activity.

    2. Network Intrusion Detection Monitor
        - Review intrusion alerts.
        - Review blocked attacks.
        - Review malicious IPs.
        - Review firerwall denies.
        - Review attack vectors.
        - Use this information to identify active network threats.

    Do not invent telemetry or security events that are not available from the tools or shared intelligence record.

    THREAT DETECTION

    For each meaningful threat identified, provide:

    - threat name/description.
    - threat category.
    - severity.
    - avilable supporting evidence.
    - affected systems when they can be reasonably be identified

    Use the configured threat taxonomy where applicable:

    {THREAT_CATEGORIES}

    Use the configured severity taxonomy:

    {SEVERITY_LEVELS}

    Do not treat every security event or blocked attack as confirmed compromise. Distinguish between:

    - normal/background activity
    - suspicious activity
    - attempted attacks
    - successfully detected malicious activity
    - evidence suggesting actual compromise

    Correlate SIEM and Network IDS whenever possible.'

    THREAT SEVERITY SCORE - VERY IMPORTANT

    Produce an overall 'threat_severity_score' between 0 and 100. 

    This score MUST be your own LLM-based cybersecurity judgement.

    You MUST NOT calculate the score using a hard-coded Python formula such as:

    - number of alerts multiplieed by a constant
    - weighted severity counts
    - percentage of critical events
    - a fixed mapping from severity labels
    - any other deterministic scoring equation

    Instead, reason over the complete evidence, including:

    - volume and severity of security events
    - critical/high severity alerts
    - failed authentication activity
    - intrusion attempts
    - malicious IP activity
    - attack vectors
    - evidence of active attacks
    - evidence suggesting compromise
    - potential impact to the organization

    The score should represent the overall threat severity of the observed security situation.
    """