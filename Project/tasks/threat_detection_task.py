"""
Threat Detection task.

Implement build_threat_detection_task(agent, state) and the
DetectionAssessment output schema.

The task instructs the agent to detect threats and judge a
threat_severity_score.

See the problem description for the output fields and the schema.
"""

from typing import Any, Dict, List

from crewai import Agent, Task
from pydantic import BaseModel, Field

from core.config import SEVERITY_LEVELS, THREAT_CATEGORIES


class ThreatFinding(BaseModel):
    """Structured representation of a detected threat."""

    threat: str = Field(
        ...,
        description="Name or concise description of the detected threat.",
    )

    category: str = Field(
        ...,
        description=(
            "Threat category. Prefer one of the configured threat "
            "categories when applicable."
        ),
    )

    severity: str = Field(
        ...,
        description=(
            "LLM-assessed severity: critical, high, medium, low, "
            "or informational."
        ),
    )

    evidence: str = Field(
        ...,
        description=(
            "Evidence from SIEM events and/or network IDS signals "
            "supporting the detected threat."
        ),
    )

    affected_systems: List[str] = Field(
        default_factory=list,
        description=(
            "Systems or assets that appear to be affected based on "
            "the available detection evidence."
        ),
    )


class DetectionAssessment(BaseModel):
    """Structured output produced by the Threat Detection specialist."""

    threat_data: List[ThreatFinding] = Field(
        default_factory=list,
        description=(
            "Threats detected from the available SIEM and network IDS "
            "evidence."
        ),
    )

    threat_severity_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description=(
            "Overall threat severity score from 0 to 100. This value "
            "MUST be the LLM's own evidence-based cybersecurity "
            "judgment and MUST NOT be calculated using a hard-coded "
            "formula."
        ),
    )

    compromised_systems: int = Field(
        ...,
        ge=0,
        description=(
            "Number of systems assessed as potentially compromised "
            "based on the available detection evidence."
        ),
    )

    detected: bool = Field(
        ...,
        description=(
            "True when meaningful cybersecurity threats are detected "
            "from the available evidence."
        ),
    )


def build_threat_detection_task(
    agent: Agent,
    state: Dict[str, Any],
) -> Task:
    """
    Build the threat-detection CrewAI task.

    The task instructs the LLM to use SIEM and network IDS data,
    identify meaningful threats, assess affected systems, and
    independently judge the overall threat severity score.
    """

    organization = state.get("organization", "UNKNOWN")

    description = f"""
You are the Threat Detection specialist for:

Organization: {organization}

Your responsibility is to identify meaningful cybersecurity threats
from the organization's available SIEM and network intrusion-detection
evidence.

SHARED INTELLIGENCE RECORD:
{state}

You MUST use both deterministic security-data sources before completing
your assessment:

1. SIEM Event Monitor
   - Review the number and severity of security events.
   - Review alerts raised.
   - Review severity distribution.
   - Review event sources.
   - Review failed authentication attempts.
   - Use this information to identify suspicious or potentially
     malicious activity.

2. Network Intrusion Detection Monitor
   - Review intrusion alerts.
   - Review blocked attacks.
   - Review malicious IPs.
   - Review firewall denies.
   - Review attack vectors.
   - Use this information to identify active network threats.

Do not invent telemetry or security events that are not available from
the tools or shared intelligence record.

THREAT DETECTION

Identify meaningful cybersecurity threats supported by the available
evidence.

For every meaningful threat, provide:

- threat name/description
- threat category
- severity
- supporting evidence
- affected systems when they can reasonably be identified

Use the configured threat taxonomy where applicable:

{THREAT_CATEGORIES}

Use the configured severity taxonomy:

{SEVERITY_LEVELS}

Do not treat every security event or blocked attack as a confirmed
compromise. Distinguish between:

- normal/background activity
- suspicious activity
- attempted attacks
- successfully detected malicious activity
- evidence suggesting actual compromise

Correlate SIEM and network IDS evidence when possible.

THREAT SEVERITY SCORE — VERY IMPORTANT

Produce an overall `threat_severity_score` between 0 and 100.

This score MUST be your own LLM-based cybersecurity judgment.

You MUST NOT calculate the score using a hard-coded Python formula such
as:

- number of alerts multiplied by a constant
- weighted severity counts
- percentage of critical events
- a fixed mapping from severity labels
- any other deterministic scoring equation

Instead, reason over the complete evidence, including:

- volume and severity of security events
- critical/high severity alerts
- failed authentication activity
- intrusion attempts
- malicious IP activity
- attack vectors
- evidence of active attacks
- evidence suggesting compromise
- potential impact to the organization

The score should represent the overall threat severity of the observed
security situation.

COMPROMISED SYSTEMS

Determine the number of systems that appear to be compromised based on
the available detection evidence.

Do not invent specific compromised systems when the available evidence
does not support them.

DETECTED

Set `detected` to true when the evidence supports meaningful
cybersecurity threats. Set it to false only when the available evidence
does not support a meaningful detected threat.

QUALITY REQUIREMENTS

Your assessment must be evidence-based.

Do not simply copy the raw tool output.

Correlate related observations where appropriate. For example, a large
number of failed authentication attempts combined with network
intrusion activity may indicate a broader attack pattern.

The detection stage should establish the initial threat picture for
the subsequent Threat Analysis specialist.

Return ONLY the structured assessment represented by the required
DetectionAssessment schema.
"""

    return Task(
        description=description,
        expected_output=(
            "A structured DetectionAssessment containing threat_data, "
            "the LLM-judged threat_severity_score, compromised_systems, "
            "and detected."
        ),
        agent=agent,
        output_pydantic=DetectionAssessment,
    )
