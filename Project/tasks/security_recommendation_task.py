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

    title: str = Field(
        ...,
        description = (
            "Short descriptive title for the recommendation."
        ),
    )