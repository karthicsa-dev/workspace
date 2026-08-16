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
            "Prioritized implementation roadmap for the recommended security improvements."
        ),
    )

    recommendations_count: int = Field(
        ...,
        ge = 0,
        description = (
            "Number of security recommendations produced.."
        ),
    )

    confidence: int = Field(
        ...,
        ge = 0.0,
        le = 1.0,
        description = (
            "LLM confidence in the overall security recommendation assessment, expressed as value from 0.0 to 1.0."
        ),
    )

    rationale: int = Field(
        ...,
        description = (
            "Reasoning explaining why the recommendations were prioritized in the selected order."
        ),
    )

    report: int = Field(
        ...,
        description = (
            "Complete markdown security intelligence report containing executive summary, key findings, incident response, prioritized recommendations, next steps, and human-review context where applicable."
        ),
    )