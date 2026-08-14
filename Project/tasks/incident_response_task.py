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
            "Category of the response action, "
        )
    )