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
        -  Review relevant vuln

    """