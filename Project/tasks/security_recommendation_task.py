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

    Your responsibility is to synthesize the complete threat-intelligence record and produce prioritized security improvements and a final security intelligence report.

    SHARED INTELLIGENCE RECORD:
    {state}

    Before producing your recommendations, use BOTH deterministic tools:

    1. Compliance Framework Benchmark
        - Review the organization's current standing against relevant security/compliance frameworks.
        - Identify meaningful control or compliance gaps.
        - Map recommendations to appropriate frameworks.

    2. Security Posture Audit
        - Review the organization's overall security posture.
        - Identify weaknesses, control deficiencies, and areas requiring improvement.
        - Use the posture findings together with the incident evidence when prioritizing recommendations.

    Do not invent compliance or posture findings that are not available  from the tools or sahred intelligence record.

    SYNTHESIS REQUIREMENTS

    Consider all available evidence, including:

    - detected threats
    - threat severity
    - compromised systems
    - threat actors
    - indicators of compromise
    - attack techniques
    - lateral movements
    - persistent mechanisms
    - data extrafiltration
    - forensic findings
    - containment requirements
    - critical assets and crown-jewel systems
    - vulnerabilities
    - compliance gaps
    - security posture weaknesses
    - potential financial, operational and reputational impact

    Produce a prioritized list of security recommendations.

    Each recommendation must include:

    - a unique priority rank
    - a concise title
    - severity
    - relevant security/compliance framework mapping
    - a practical description of the recommended improvement

    Prioritize recommendations based on:

    1. Immediate risk to the organization.
    2. Active compromise and containment requirements.
    3. Protection of critical and crown-jewel assets.
    4. Likelihood and impact of recurrence.
    5. Exploitable vulnerabilities and controllable weaknesses.
    6. Compliance/security-framework gaps.
    7. Long-term security resiliance.

    Do not simply repeat the incident-response actions. Recommendations should address both immediate remediation and longer-term security improvements.

    ROADMAP

    Create a practical implementation roadmap.

    Where applicable, use the time horizons such as:

    - 0-72 Hours
    - 1-4 Weeks
    - 1-6 Months
    - Ongoing

    Each roadmap item must identify:

    - initiative
    - timeframe
    - priority
    - expected impact

    CONFIDENCE

    Provide a confidence value between 0.0 and 1.0 representing your confidence in the overall recommendation assessment based on the available evidence.

    RATIONALE

    Explain the reasoning behind the prioritization. The rationale should connect the recommendations to the observed threats, affected assets, business impace, compliance posture, and security posture.

    FINAL REPORT

    Produce a complete Markdown security intelligence report.

    The report should contain, where applicable:

    # Security Intelligence Report

    ## Executive Summary

    Summarize the overall security situation, major threats, severity, business impact, and immediate concerns.

    ## Key Findings

    Summarize the most important threat-analysis and forensic findings.

    ## Incident Response

    Summarize the response actions, containment strategy, and relevant forensic findings.

    ## Prioritized Recommendations

    Present the prioritized security recommendations and their framework mapping.

    ## Next steps

    Present the recommended implementation roadmap and immediate actions.

    ## Human Review - Critical Incident

    If the intelligence record indicates that human review is required, clearly identify that the incident requires SOC analyst review and approval before the containment plan is adopted.

    If the human review is not required, do not incorrectly state that a critical incident is awaiting approval.

    The report must be useful to both technical security personnel and business stakeholders.

    Return ONLY the structured assessment represented by the required RecommendationAssessment schema.

    """

    return Task(
        description=description,
        expected_output=(
            "A structured RecommendationAssessment containing security_recommendations, roadmap, recommendations_count, confidence, rationale and a complete Markdown report."
        ),
        agent=agent,
        output_pydantic=RecommendationAssessment,
    )