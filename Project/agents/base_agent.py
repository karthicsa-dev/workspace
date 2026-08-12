"""
Base threat agent.

Implement BaseThreatAgent as the abstract base for every specialist: a constructor that builds the
crewai.Agent (stored as crewai_agent), one abstract analyze_async(state), and a concrete
execute_async(state) that retries and never raises. See the problem description for the contract.
"""
