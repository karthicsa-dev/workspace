"""
Threat Detection agent.

Implement ThreatDetectionAgent (agent_name "detector"): a pure-LLM specialist that detects threats
and judges a threat_severity_score.
See the problem description for its tools, the result keys, and the schema.
"""
from typing import Any, Dict
from crewai import Crew, Process

from agents.base_agent import BaseThreatAgent
from tasks.threat_detection_task import build_threat_analysis_task