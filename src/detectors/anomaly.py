"""Behavioral anomaly detection for agents."""
import math, logging
from typing import Dict, List, Optional
from collections import deque
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class AnomalyResult(BaseModel):
    is_anomalous: bool
    score: float
    deviations: Dict[str, float]
    explanation: str

class BehaviorBaseline:
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self._response_lengths: deque = deque(maxlen=window_size)
        self._action_counts: Dict[str, int] = {}
        self._tool_usage: Dict[str, int] = {}
    
    def record(self, response_length: int, actions: List[str] = None, tools: List[str] = None):
        self._response_lengths.append(response_length)
        for action in (actions or []):
            self._action_counts[action] = self._action_counts.get(action, 0) + 1
        for tool in (tools or []):
            self._tool_usage[tool] = self._tool_usage.get(tool, 0) + 1
    
    @property
    def mean_length(self) -> float:
        if not self._response_lengths:
            return 0.0
        return sum(self._response_lengths) / len(self._response_lengths)
    
    @property
    def std_length(self) -> float:
        if len(self._response_lengths) < 2:
            return 1.0
        mean = self.mean_length
        variance = sum((x - mean) ** 2 for x in self._response_lengths) / len(self._response_lengths)
        return max(math.sqrt(variance), 1.0)

class AnomalyDetector:
    def __init__(self, z_threshold: float = 2.5):
        self.z_threshold = z_threshold
        self._baselines: Dict[str, BehaviorBaseline] = {}
    
    def get_baseline(self, agent_id: str) -> BehaviorBaseline:
        if agent_id not in self._baselines:
            self._baselines[agent_id] = BehaviorBaseline()
        return self._baselines[agent_id]
    
    def check(self, agent_id: str, response_length: int, actions: List[str] = None, tools: List[str] = None) -> AnomalyResult:
        baseline = self.get_baseline(agent_id)
        deviations = {}
        
        if len(baseline._response_lengths) >= 10:
            z_score = abs(response_length - baseline.mean_length) / baseline.std_length
            deviations["response_length_z"] = round(z_score, 2)
        
        baseline.record(response_length, actions, tools)
        
        max_dev = max(deviations.values()) if deviations else 0.0
        is_anomalous = max_dev > self.z_threshold
        
        return AnomalyResult(
            is_anomalous=is_anomalous,
            score=min(max_dev / self.z_threshold, 1.0) if self.z_threshold > 0 else 0.0,
            deviations=deviations,
            explanation=f"Z-score {max_dev:.1f} {'exceeds' if is_anomalous else 'within'} threshold {self.z_threshold}",
        )
