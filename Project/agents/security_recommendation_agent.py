"""
Security Recommendation agent.

Implement SecurityRecommendationAgent (agent_name "advisor"): a pure-LLM specialist that produces
prioritised security recommendations and a report.
See the problem description for its tools, the result keys, and the schema.
"""
from typing import Any, Dict
from crewai import Crew, Process

from agents.base_agent import BaseThreatAgent
from tasks.security_recommendation_task import (
    build_security_recommendation_task,
)
from tools.compliance_benchmark_tool import compliance_benchmark_tool
from tools.security_posture_tool import security_posture_tool
from utils.llm_config import get_llm

class SecurityRecommendationAgent(BaseThreatAgent):
    agent_name = "advisor"

    def __init__(self) -> None:
        super().__init__(
            role="Cybersecurity Security Recommendation specialist",
            goal="Synthesize the threat intelligence, threat analysis, incident-response findings, compliance posture, and security posture into prioritized security recommendations. Produce a practical remidiation roadmap and a clear security intelligence report.",
            backstory="You are an experienced cybersecurity security architect and risk advisor. Ypu assess an organization's security"
        )