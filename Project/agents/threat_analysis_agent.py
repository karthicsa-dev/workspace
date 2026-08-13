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
            backstory=(
                "You are an experienced cyber threat intelligence analyst specializing in threat attribution, adversary behavior, attack techniques, and incident severity assessment. You correlate internal endpoint evidence with external threat intelligence to understand the active threat landscape. Your critical-threat count must reflect your reasoned assessment of the evidence rather than a hard-coded formula or arbitary threshold."
            ),
            llm=get_llm(
                temperature=0.2,
                max_tokens=2000,
            ),
            tools=[
                threat_intel_feed_tool,
                endpoint_telemetry_tool,
            ],
        )
    
    async def analyze_async(self, state: Dict[str, Any]) -> Dict[str, Any]:
        task = build_threat_analysis_task(
            agent=self.crewai_agent,
            state=state,
        )

        crew = Crew(
            agents=[self.crewai_agent],
            tasks=[task],
            process=Process.sequential,
            verbose=False,
        )

        result = await crew.kickoff_async()

        assessment = result.pydantic

        if assessment is None:
            raise ValueError(
                "Threat Analysis task did not return a structured AnalysisAssessment."
            )

        if hasattr(assessment, "model_dump"):
            data = assessment.model_dump()

        elif hasattr(assessment, "dict"):
            data = assessment.dict()

        else:
            raise TypeError(
                "Threat analysis task returned an unexpected structured-output type."
            )
        
        return {
            "threat_analysis": data.get(
                "threat_analysis",
                "",
            ),
            "critical_threats": data.get(
                "critical_threats",
                0,
            ),
            "analyzed": data.get(
                "analyzed",
                True,
            ),
        }