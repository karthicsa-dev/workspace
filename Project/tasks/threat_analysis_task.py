"""
Threat Analysis task.

Implement build_threat_analysis_task(agent, state) and the AnalysisAssessment output schema.
The task instructs the agent to analyze the threats and count the critical_threats.
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

    threat_actor: str = Field(
        default="UNKNOWN",
        description = (
            "Threat actor or adversary attributed to the threat when supported by the available evidence."
        ),
    )

    techniques: List[str] = Field(
        default_factory=list,
        description = (
            "MITRE ATT&CK techniques or attack behaviors associated with the threat when supported by the evidence."
        ),
    )

    evidence: str = Field(
        ...,
        description = (
            "Evidence from threat intelligence and endpoint telemetry supporting the analysts."
        ),
    )

    business_impact: str = Field(
        ...,
        description = (
            "Potential financial, operational and reputational impact of the threat."
        ),
    )

class AnalysisAssessment(BaseModel):
    threat_analysis: List[ThreatFinding] = Field(
        default_factory = list,
        description = (
            "Detailed analysis and attribution of the threats identified from the available intelligence and endpoint evidence."
        ),
    )

    threat_severity_score: float = Field(
        ...,
        ge = 0.0,
        le = 100.0,
        description = (
            "Overall threat severity score from 0 to 100. This value MUST be the LLM's own evidence based cybersecurity judgement and MUST NOT be calculated using a hard-coded formula."
        ),
    )

    compromised_systems: int = Field(
        ...,
        ge = 0,
        description = (
            "Number of systems assessed as potentially compromised based on the available detection evidence."
        ),
    )

    detected: bool = Field(
        ...,
        description = (
            "True when meaningful cybersecurity threats are detected from the available evidence."
        ),
    )

def build_threat_detection_task(agent: Agent, state: Dict[str, Any]) -> Task:
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

    
    """

    return Task(
        description=description,
        expected_output=(
            "A structured AnalysisAssessment containing threat_analysis, the LLM-judged critical_threats count and analyzed."
        ),
        agent=agent,
        output_pydantic=AnalysisAssessment,
    )