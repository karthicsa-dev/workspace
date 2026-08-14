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
            "Relevant security "
        ),
    )