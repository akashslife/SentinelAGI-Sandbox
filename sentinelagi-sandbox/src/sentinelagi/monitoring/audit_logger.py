"""
Redis Audit Logger

Intercepts all tool invocations, logs them to a Redis audit stream,
and raises alerts when agents attempt privilege escalation or call
tools outside their declared scope.
"""

import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import redis.asyncio as redis

from sentinelagi.core.config import get_settings
from sentinelagi.core.models import AuditEvent, SecurityAlert

logger = logging.getLogger(__name__)


class AuditLogger:
    """Logs all agent actions to Redis streams for audit and monitoring."""
    
    def __init__(self):
        self.config = get_settings().redis
        self._redis: Optional[redis.Redis] = None
        self._connected = False
    
    async def _get_redis(self) -> redis.Redis:
        """Get or create Redis connection."""
        if self._redis is None or not self._connected:
            try:
                self._redis = redis.Redis(
                    host=self.config.host,
                    port=self.config.port,
                    db=self.config.db,
                    password=self.config.password,
                    ssl=self.config.ssl,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_keepalive=True,
                )
                await self._redis.ping()
                self._connected = True
                logger.info("Redis audit logger connected")
            except Exception as e:
                logger.error(f"Redis connection failed: {e}")
                self._connected = False
                # Return dummy connection that logs to file
                return None
        return self._redis
    
    async def log_event(self, event: AuditEvent) -> Optional[str]:
        """
        Log an audit event to Redis stream.
        
        Returns:
            Stream entry ID if successful
        """
        try:
            r = await self._get_redis()
            
            if r is None:
                # Fallback: log to file
                await self._log_to_file(event)
                return None
            
            # Add to stream with maxlen to prevent unbounded growth
            entry_id = await r.xadd(
                self.config.audit_stream,
                event.to_redis_dict(),
                maxlen=self.config.stream_maxlen,
                approximate=True,
            )
            
            # Set TTL on stream entries (cleanup old entries)
            await r.expire(self.config.audit_stream, self.config.stream_ttl)
            
            # Update metrics counters
            await self._update_metrics(event)
            
            logger.debug(f"Audit event logged: {event.event_id} -> {entry_id}")
            return entry_id
        
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            await self._log_to_file(event)
            return None
    
    async def log_alert(self, alert: SecurityAlert) -> Optional[str]:
        """
        Log a security alert and publish to alert channel.
        
        Returns:
            Stream entry ID if successful
        """
        try:
            r = await self._get_redis()
            
            if r is None:
                await self._log_alert_to_file(alert)
                return None
            
            # Add to alert stream
            alert_data = {
                "alert_id": alert.alert_id,
                "timestamp": alert.timestamp.isoformat(),
                "level": alert.level.value,
                "agent_id": alert.agent_id,
                "session_id": alert.session_id,
                "alert_type": alert.alert_type,
                "message": alert.message,
                "mitre_technique_id": alert.mitre_technique_id or "",
                "context": json.dumps(alert.context),
                "acknowledged": str(alert.acknowledged),
            }
            
            entry_id = await r.xadd(
                f"{self.config.audit_stream}:alerts",
                alert_data,
                maxlen=10000,
                approximate=True,
            )
            
            # Publish to alert channel for real-time subscribers
            await r.publish(
                self.config.alert_channel,
                json.dumps(alert_data),
            )
            
            logger.warning(
                f"Security Alert [{alert.level.value.upper()}]: {alert.message} "
                f"(Agent: {alert.agent_id})"
            )
            
            return entry_id
        
        except Exception as e:
            logger.error(f"Failed to log alert: {e}")
            await self._log_alert_to_file(alert)
            return None
    
    async def get_recent_events(
        self,
        count: int = 100,
        agent_id: Optional[str] = None,
    ) -> List[AuditEvent]:
        """Get recent audit events from stream."""
        try:
            r = await self._get_redis()
            if r is None:
                return []
            
            # Read last N entries
            entries = await r.xrevrange(
                self.config.audit_stream,
                count=count,
            )
            
            events = []
            for entry_id, fields in entries:
                if agent_id and fields.get("agent_id") != agent_id:
                    continue
                
                events.append(AuditEvent(
                    event_id=fields.get("event_id", ""),
                    timestamp=datetime.fromisoformat(fields.get("timestamp", "")),
                    action_type=fields.get("action_type", "tool_call"),
                    agent_id=fields.get("agent_id", ""),
                    session_id=fields.get("session_id", ""),
                    tool_name=fields.get("tool_name") or None,
                    authorized=fields.get("authorized", "True") == "True",
                ))
            
            return events
        
        except Exception as e:
            logger.error(f"Failed to get recent events: {e}")
            return []
    
    async def get_event_statistics(self) -> Dict[str, Any]:
        """Get aggregate statistics from audit stream."""
        try:
            r = await self._get_redis()
            if r is None:
                return {}
            
            # Get stream info
            info = await r.xinfo_stream(self.config.audit_stream)
            
            # Get metrics
            metrics = await r.hgetall(f"{self.config.metrics_key_prefix}:totals")
            
            return {
                "total_events": info.get("length", 0),
                "consumer_groups": len(info.get("groups", [])),
                "metrics": metrics,
            }
        
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
    
    async def _update_metrics(self, event: AuditEvent) -> None:
        """Update aggregate metrics."""
        try:
            r = await self._get_redis()
            if r is None:
                return
            
            pipe = r.pipeline()
            
            # Increment counters
            pipe.hincrby(f"{self.config.metrics_key_prefix}:totals", "total_events", 1)
            pipe.hincrby(
                f"{self.config.metrics_key_prefix}:by_agent",
                event.agent_id,
                1,
            )
            pipe.hincrby(
                f"{self.config.metrics_key_prefix}:by_action",
                event.action_type if isinstance(event.action_type, str) else event.action_type.value,
                1,
            )
            
            if not event.authorized:
                pipe.hincrby(f"{self.config.metrics_key_prefix}:totals", "denied_events", 1)
            
            if event.mitre_technique_id:
                pipe.hincrby(
                    f"{self.config.metrics_key_prefix}:mitre",
                    event.mitre_technique_id,
                    1,
                )
            
            await pipe.execute()
        
        except Exception as e:
            logger.error(f"Failed to update metrics: {e}")
    
    async def _log_to_file(self, event: AuditEvent) -> None:
        """Fallback: log to file when Redis is unavailable."""
        try:
            import aiofiles
            
            log_line = f"{event.timestamp.isoformat()} | {event.action_type} | {event.agent_id} | {event.tool_name or 'N/A'} | authorized={event.authorized}\n"
            
            async with aiofiles.open("audit_fallback.log", "a") as f:
                await f.write(log_line)
        
        except Exception as e:
            logger.error(f"Even file fallback logging failed: {e}")
    
    async def _log_alert_to_file(self, alert: SecurityAlert) -> None:
        """Fallback: log alert to file."""
        try:
            import aiofiles
            
            log_line = f"ALERT [{alert.level.value}] {alert.timestamp.isoformat()}: {alert.message} (Agent: {alert.agent_id})\n"
            
            async with aiofiles.open("alerts_fallback.log", "a") as f:
                await f.write(log_line)
        
        except Exception as e:
            logger.error(f"Even file alert logging failed: {e}")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Redis health and connection status."""
        try:
            r = await self._get_redis()
            if r is None:
                return {
                    "status": "degraded",
                    "mode": "file_fallback",
                    "redis_connected": False,
                }
            
            info = await r.info()
            return {
                "status": "healthy",
                "mode": "redis",
                "redis_connected": True,
                "redis_version": info.get("redis_version"),
                "used_memory_human": info.get("used_memory_human"),
                "connected_clients": info.get("connected_clients"),
            }
        
        except Exception as e:
            return {
                "status": "degraded",
                "mode": "file_fallback",
                "redis_connected": False,
                "error": str(e),
            }


# Singleton
audit_logger = AuditLogger()
