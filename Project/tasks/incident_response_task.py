"""
Incident Response task.

Implement build_incident_response_task(agent, state) and the ResponseAssessment output schema.
The task instructs the agent to build an incident-response plan.
See the problem description for the output fields and the schema.
"""
from typing import Any, Dict, List

from crewai import Agent, task
from pydantic import BaseModel, Field

class ResponseAction(BaseModel):
    stage: str = Field(
        ...,
        description = (
            "Incident-response lifecycle stage for this action. Use identification, containment, eradication, recovery, or lessons learned."
        ),
    )

    category: str = Field(
        ...,
        description = (
            "Category of the response action, such as endpoint, network, identity, vulnerability, or data protection."
        ),
    )

    action: str = Field(
        ...,
        description = (
            "Specific actionable response or containment step."
        ),
    )

    target: str = Field(
        ...,
        description = (
            "System, asset, infrastructure component, identity system, or other target to which the action applies."
        ),
    )

class ForensicFinding(BaseModel):
    finding: str = Field(
        ...,
        description = (
            "Observing or inferred forensic finding."
        ),
    )

    evidence: str = Field(
        ...,
        description = (
            "Evidence supporting the forensic finding."
        ),
    )

    significance: str = Field(
        ...,
        description = (
            "Security significance of the finding."
        ),
    )

class ResponseAssessment(BaseModel):
    response_actions: List[ResponseAction] = Field(
        default_factory=list,
        description = (
            "Prioritized incident-response actions covering appropriate response lifecycle stages."
        ),
    )

    forensic_findings: List[ForensicFinding] = Field(
        default_factory=list,
        description = (
            "Forensic Findings derived from the available threat, asset, and vulnerability evidence."
        ),
    )

    containment_summary: str = Field(
        ...,
        description = (
            "Concise summary of the recommended containment approach, including the most important immediate containment measures."
        ),
    )

    responded: str = Field(
        ...,
        description = (
            "True when a meaningful incident-response plan has been successfully developed from the available evidence."
        ),
    )

def build_incident_response_task(agent: Agent, state: Dict[str, Any]) -> Task:
    organization = state.get("organization", "UNKNOWN")

    description = f""" 
    You are responsible for developing the incident-response plan for:

    Organization: {organization}

    Review the complete shared intelligence record below before producing your assessment.

    SHARED INTELLIGENCE RECORD:
    {state}

    Your task is to determine the appropriate incident-response actions based on the threats already detected and analyzed.

    You MUST use the available deterministic tools to obtain the relevant asset inventory and vulnerability information before finalizing the plan:

    1. Asset Inventory System
        -  Identify affected systems and assets.
        -  Identify critical assets and crown-jewel systems.
        -  Determine relevant network segments and exposed assets.
        -  Use this information to identify appropriate containment targets.

    2. Vulnerability Scanner
        -  Review relevant vulnerability findings.
        -  Identify weaknesses that may contribute to the incident.
        -  Use the findings to support containment, eradication and remediation decisions.

    Do not invent asset or vulnerability data that is not available from the tools or shared intelligence record.

    Develop a practical incident-response plan covering the applicable incident-response lifecycle stages:
    -  identificaton
    -  containment
    -  eradication
    -  recovery
    -  lessons learned

    For each response action, provide:
    -  the lifecycle stage
    -  the action category
    -  the specific action
    -  the target system or asset

    Also identify important forensic findings and explain the evidence and security significance of each finding.

    The containment summary must clearly explain the immediate containment strategy, particularly for critical or compromised systems.

    Use cybersecurity judgement to prioritize actions according to:
    -  severity of the active threat
    -  affected systems
    -  criticality of assets
    -  evidence of compromise
    -  lateral movement
    -  persistance
    -  data extrafiltration
    -  relevant vulnerabilities
    -  potential business impact

    Do not merely repeat the input data. Reason over it and produce an actionable response plan.

    Return ONLY the structured assessment represented by the required ResponseAssessment schema.
    """

    return Task(
        description=description,
        expected_output=(
            "A structured ResponseAssessment containing response_actions, forensic_findings, containment_summary, and responded."
        ),
        agent=agent,
        output_pydantic=ResponseAssessment,
    )
    