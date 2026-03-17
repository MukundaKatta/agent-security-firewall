"""agent-security-firewall — anomaly module. Security middleware protecting AI agents from prompt injection"""
import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class AnomalyConfig(BaseModel):
    """Configuration for Anomaly."""
    name: str = "anomaly"
    enabled: bool = True
    max_retries: int = 3
    timeout: float = 30.0
    options: Dict[str, Any] = field(default_factory=dict) if False else {}


class AnomalyResult(BaseModel):
    """Result from Anomaly operations."""
    success: bool = True
    data: Dict[str, Any] = {}
    errors: List[str] = []
    metadata: Dict[str, Any] = {}


class Anomaly:
    """Core Anomaly implementation for agent-security-firewall."""
    
    def __init__(self, config: Optional[AnomalyConfig] = None):
        self.config = config or AnomalyConfig()
        self._initialized = False
        self._state: Dict[str, Any] = {}
        logger.info(f"Anomaly created: {self.config.name}")
    
    async def initialize(self) -> None:
        """Initialize the component."""
        if self._initialized:
            return
        await self._setup()
        self._initialized = True
        logger.info(f"Anomaly initialized")
    
    async def _setup(self) -> None:
        """Internal setup — override in subclasses."""
        pass
    
    async def process(self, input_data: Any) -> AnomalyResult:
        """Process input and return results."""
        if not self._initialized:
            await self.initialize()
        try:
            result = await self._execute(input_data)
            return AnomalyResult(success=True, data={"result": result})
        except Exception as e:
            logger.error(f"Anomaly error: {e}")
            return AnomalyResult(success=False, errors=[str(e)])
    
    async def _execute(self, data: Any) -> Any:
        """Core execution logic."""
        return {"processed": True, "input_type": type(data).__name__}
    
    def get_status(self) -> Dict[str, Any]:
        """Get component status."""
        return {"name": "anomaly", "initialized": self._initialized,
                "config": self.config.model_dump()}
    
    async def shutdown(self) -> None:
        """Graceful shutdown."""
        self._state.clear()
        self._initialized = False
        logger.info(f"Anomaly shut down")
