"""
Threat Analysis agent.

Implement ThreatAnalysisAgent (agent_name "analyst"): a pure-LLM specialist that attributes threats
and counts the critical_threats.
See the problem description for its tools, the result keys, and the schema.
"""
from typing import Any, Dict
from crewai import Crew, Process

from agents.base_agent import BaseThreatAgent
from tasks.threat_analysis_task import build_threat_analysis_task
from tools.endpoint_telemetry_tool import endpoint_telemetry_tool
from tools.threat_intel_feed_tool import threat_intel_feed_tool
from utils.llm_config import get_llm

class ThreatAnalysisAgent(BaseThreatAgent):
    agent_name = "analyst"

    def __init__(self) -> None:
        super().__init__(
            role="Cybersecurity Threat Analysis Specialist",
            goal=(
                "Analyze and attribute the deetcted threats using available threat-intelligence and endpoint telemetry data. determine the severity and significance of each threat and use your own cybersecurity judgement to identify how many threats should be classified as critical."
            ),
            backstory=
        )