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
    You are the threat analysis specialist for:

    Organization: {organization}

    Analyze the threats identified during the detection stage and determine thier likely attribution , severity, attack behavior and business impact.

    SHARED INTELLIGENCE RECORD: 
    {state}

    You MUST use both of your deterministic data sources before completing the assessment:

    1. Threat Intelligence Feed
        - Review active threat actors.
        - Review matched indicators of compromise.
        - Review known malware families.
        - Review linked campaigns.
        - Use this evidence to support threat attribution.

    2. Endpoint Detection and Response Telemetry
        - Review compromised endpoints.
        - Review process anamolies.
        - Review lateral movement.
        - Review persistence mechanisms.
        - Review evidence of data extrafiltration.
        - Use this evidence to establish whether threats are active and whether systems appear compromised.

    Do not invent t
    """