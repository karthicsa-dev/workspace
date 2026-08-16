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

    Do not invent threat-intelligence or endpoint evidence that is not available from the tools or shared intelligence record.

    THREAT ANALYSIS

    For each meaningful threat identified:

    - Identify the threat.
    - Classify it using appropriate threat category.
    - Assess its severity.
    - Attribute it to a threat actor when the avilable evidence supports attribution.
    - Identify relevant MITRE ATT&CK techniques or attack behaviors where supported by evidence.
    - Explain the evidence supporting the finding.
    - Explain the potential business impact.

    Use the configured threat taxonomy where applicable:

    {THREAT_CATEGORIES}

    Use the configured severity taxonomy:

    {SEVERITY_LEVELS}

    Do not simply copy values from the input. Correlate the available evidence and apply cybersecurity reasoning.

    CRITICAL THREAT JUDGEMENT - VERY IMPORTANT

    You MUST independently determine the number of critical threats based on your analysis of the complete evidence.

    The value of 'critical_threats':

    - MUST be your own LLM Judgement.
    - MUST represent the number of threats you determine are genuinely critical.
    - MUST consider severity, evidence of active compromise, affected systems, attack progression, persistence, lateral movement, exfiltration, threat-actor activity and potential business impact.
    - MUST NOT be calculated using python formula.
    - MUST NOT simply count records whose input severity happens to be "critical"
    - MUST NOT be derived from the configured critical-threat floor.
    - MUST NOT be artifically increased or decreased to force a particular outcome.

    The router will independently compare your resulting 'critical_threats' value against the configured policy floor.

    Your responsibility ends with making the best evidence-based cybersecurity judgement.

    ANALYSIS QUALITY

    Correlate external threat intelligence with internal endpoint evidence.

    For example, when threat-intelligence evidence identifies a known threat actor or malware family and endpoint telemetry independently shows behavior consistent with threat, explain the correlation rather than treating the two observations as unrelated facts.

    Pay particular attention to:

    - confirmed compromise
    - lateral movement
    - persistence
    - data exfiltration
    - malicious processes
    - matched IOCs
    - active campaigns
    - critical business systems
    - potential operational disruption
    - potential financial and reputational impact

    Return ONLY the structured assessment represented by the required AnalysisAssessment schema.
    """

    return Task(
        description=description,
        expected_output=(
            "A structured AnalysisAssessment containing threat_analysis, the LLM-judged critical_threats count and analyzed."
        ),
        agent=agent,
        output_pydantic=AnalysisAssessment,
    )