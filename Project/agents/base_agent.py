"""
Base threat agent.

Implement BaseThreatAgent as the abstract base for every specialist: a constructor that builds the
crewai.Agent (stored as crewai_agent), one abstract analyze_async(state), and a concrete
execute_async(state) that retries and never raises. See the problem description for the contract.
"""
import asyncio
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from crewai import Agent
from core.config import config

class BaseThreatAgent(ABC):
    