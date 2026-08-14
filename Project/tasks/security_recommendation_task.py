"""
Security Recommendation task.

Implement build_security_recommendation_task(agent, state) and the RecommendationAssessment output
schema. The task instructs the agent to produce prioritised recommendations and a report.
See the problem description for the output fields and the schema.
"""
from typing import Any, Dict, List

from crewai import Agent, task
from pydantic import BaseModel, Field

class SecurityRecommendation(BaseModel):
    priority: int = Field(
        ...,
        ge = 1,
        description = (
            "Priority rank of recommendation. 1 represents the highest priority."
        ),
    )

    title: str = Field(
        ...,
        description = (
            "Short descriptive title for the recommendation."
        ),
    )

    severity: str = Field(
        ...,
        description = (
            "Risk/severity classification of the recommendation, such as Critical, High, Medium or Low."
        ),
    )

    framework: str = Field(
        ...,
        description = (
            "Relevant security or compliance framework/control mapping, such as NIST CSF, CIS controls, MITRE ATT&CK, ISO 27001, or SANS Top 20."
        ),
    )

    description: str = Field(
        ...,
        description = (
            "Detailed explanation of the recommended security improvement and why it should be implemented."
        ),
    )

class RoadmapItem(BaseModel):
    initiative: str = Field(
        ...,
        description = (
            "Name of the security improvement initiative."
        ),
    )

    timeframe: str = Field(
        ...,
        description = (
            "Recommended implementation timeframe, such as 0-72 Hours, 1-4 Weeks, 1-6 Months, or Ongoing."
        ),
    )

    priority: str = Field(
        ...,
        description = (
            "Priority of the roadmap initiative."
        ),
    )

    impact: str = Field(
        ...,
        description = (
            "Expected security or business impact."
        ),
    )

class RecommendationAssessment(BaseModel):
    security_recommendations: List[SecurityRecommendation] = Field(
        default_factory = list,
        description = (
            "Prioritized security recommendations derived from the threat intelligence, incident response, compliance benchmark, and security posture findings."
        ),
    )

    roadmap: List[RoadmapItem] = Field(
        default_factory = list,
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

def build_security_recommendation_task(agent: Agent, state: Dict[str, Any]) -> Task:
    organization = state.get("organization", "UNKNOWN")

    description = f""" 
    You are the final security recommendation specialist for:

    Organization: {organization}

    Your responsibility is to synthesize the complete threat-intelligence record and produce prioritized 
    """