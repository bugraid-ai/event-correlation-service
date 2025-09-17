import json
import boto3
import asyncio
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from contextlib import asynccontextmanager

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics.pairwise import cosine_similarity
try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SentenceTransformer = None
    SENTENCE_TRANSFORMERS_AVAILABLE = False
from collections import defaultdict
import logging
import uuid
import re
try:
    from opensearchpy import OpenSearch, exceptions as os_exceptions
    OPENSEARCH_AVAILABLE = True
except ImportError:
    OpenSearch = None
    os_exceptions = None
    OPENSEARCH_AVAILABLE = False
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    REDIS_AVAILABLE = False

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from langgraph.graph import StateGraph
from langgraph.graph.message import AnyMessage, add_messages
from typing_extensions import Annotated, TypedDict

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CorrelationRequest(BaseModel):
    alerts: List[Dict[str, Any]] = Field(..., description="List of alerts to correlate")
    environment: str = Field(..., description="Environment (development or production)")
    source: str = Field(..., description="Source of the alerts")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + 'Z')

class IncidentCluster(BaseModel):
    incident_id: str
    alerts: List[Dict[str, Any]]
    cluster_size: int
    representative_alert: Dict[str, Any]
    created_timestamp: str

class CorrelationResponse(BaseModel):
    incident_clusters: List[IncidentCluster]
    total_incidents: int
    total_alerts_processed: int
    processing_time_ms: float
    timestamp: str

class WorkflowState(TypedDict):
    """State for LangGraph workflow"""
    alerts: List[Dict[str, Any]]
    environment: str
    source: str
    incident_clusters: List[Dict[str, Any]]
    total_incidents: int
    messages: Annotated[list[AnyMessage], add_messages]
    error: Optional[str]

class EventCorrelationAgent:
    """
    Agent responsible for event correlation - grouping related alerts by time, service, and similarity
    Maintains the same functionality as the correlation logic from dbscan_correlation.py
    """
    
    def __init__(self, config: Optional[Dict] = None, state: Optional[str] = None):
        self.config = config or {}
        self.state = state
        
        # Initialize SQS client instead of DynamoDB
        self.sqs = boto3.client('sqs')
        
        # Initialize Lambda client for triggering log fetcher
        self.lambda_client = boto3.client('lambda')
        # Prefer config/env over hardcoded; default to provided queue URL
        self.sqs_queue_url = (
            (self.config.get('sqs') or {}).get('queue_url')
            or os.environ.get('SQS_QUEUE_URL')
            or ("https://sqs.ap-southeast-1.amazonaws.com/528104389666/prod-events-core" 
                if os.environ.get("ENVIRONMENT") == "production" 
                else "https://sqs.ap-southeast-1.amazonaws.com/528104389666/dev-events-core")
        )
        
        # Queue mapping for different environments
        self.queue_mapping = {
            "development": {
                "incidents": "dev-events-queue",
                "timelines": "dev-timelines-queue",
                "counters": "dev-counters-queue"
            },
            "production": {
                "incidents": "prod-events-core",
                "timelines": "prod-timelines-queue",
                "counters": "prod-counters-queue"
            }
        }
        
        # Configuration parameters
        self.time_window_minutes = self.config.get('time_window_minutes', 15)
        self.similarity_threshold = self.config.get('similarity_threshold', 0.3)
        self.min_samples = self.config.get('min_samples', 2)
        self.eps = self.config.get('eps', 0.5)
        
        # Environment must be explicitly set - no defaults
        self.environment = os.environ.get('ENVIRONMENT')
        if not self.environment:
            raise ValueError("ENVIRONMENT variable must be set to either 'production' or 'development'")
        self.environment = self.environment.strip().lower()
        if self.environment not in ("production", "development"):
            raise ValueError(f"Invalid ENVIRONMENT value: {self.environment}")
        
        # Initialize sentence transformer for semantic similarity
        if SENTENCE_TRANSFORMERS_AVAILABLE:
            try:
                self.sentence_model = SentenceTransformer('all-MiniLM-L6-v2')
                logger.info("Successfully loaded SentenceTransformer model")
            except Exception as e:
                logger.warning(f"Could not load SentenceTransformer: {e}")
                logger.warning("Falling back to TF-IDF for semantic similarity")
                self.sentence_model = None
        else:
            logger.warning("sentence_transformers not available, using TF-IDF fallback")
            self.sentence_model = None
        # Track SQS acknowledgements by queue type
        self._sqs_acks: Dict[str, List[str]] = {"incidents": [], "timelines": [], "counters": []}

        # Initialize OpenSearch client for timeline storage (strict per-environment index)
        if self.environment == 'production':
            self.os_index = 'incidents'
        elif self.environment == 'development':
            self.os_index = 'dev-incidents'
        else:
            raise ValueError(f"Invalid environment for OpenSearch index: {self.environment}")
        self.os: Optional[OpenSearch] = None
        # Initialize OpenSearch (optional for development)
        if not OPENSEARCH_AVAILABLE:
            logger.warning("opensearch-py not available, OpenSearch disabled")
            self.os = None
            return
            
        # Get OpenSearch endpoint from environment variable (optional for development)
        os_host = os.environ.get('OS_HOST')
        if not os_host:
            logger.warning("OS_HOST environment variable not set, OpenSearch disabled for development")
            self.os = None
            return
        os_user = os.environ.get('OS_USER') or os.environ.get('OPENSEARCH_USER') or os.environ.get('ES_USER') or 'master'
        os_pass = os.environ.get('OS_PASS') or os.environ.get('OPENSEARCH_PASS') or os.environ.get('ES_PASS') or 'Bugraid@123'
        if os_host and os_user and os_pass:
            try:
                # Allow full URL or bare host
                if os_host.startswith('http'):
                    hosts = [os_host]
                else:
                    hosts = [{"host": os_host, "port": 443}]
                self.os = OpenSearch(
                    hosts=hosts,
                    http_auth=(os_user, os_pass),
                    use_ssl=True,
                    verify_certs=True,
                    ssl_assert_hostname=False,
                )
                logger.info("OpenSearch client initialized for timeline storage")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenSearch client: {e}")
        
        # Initialize Redis/Valkey client for incident correlation
        self.redis = None
        if REDIS_AVAILABLE:
            redis_host = os.environ.get('REDIS_HOST', 'localhost')
            redis_port = int(os.environ.get('REDIS_PORT', 6379))
            redis_username = os.environ.get('REDIS_USERNAME')
            redis_password = os.environ.get('REDIS_PASSWORD')
            
            if redis_host != 'localhost':
                try:
                    if redis_username and redis_password:
                        self.redis = redis.Redis(
                            host=redis_host,
                            port=redis_port,
                            username=redis_username,
                            password=redis_password,
                            socket_timeout=5.0,
                            socket_connect_timeout=5.0,
                            retry_on_timeout=True,
                            decode_responses=True
                        )
                    else:
                        self.redis = redis.Redis(
                            host=redis_host,
                            port=redis_port,
                            socket_timeout=5.0,
                            socket_connect_timeout=5.0,
                            retry_on_timeout=True,
                            decode_responses=True
                        )
                    
                    # Test Redis connection
                    self.redis.ping()
                    logger.info(f"Connected to Redis/Valkey at {redis_host}:{redis_port} for incident correlation")
                except Exception as e:
                    logger.warning(f"Failed to connect to Redis/Valkey at {redis_host}: {e}")
                    self.redis = None
            else:
                logger.info(f"Skipping Redis connection with REDIS_HOST={redis_host}")
        else:
            logger.warning("redis library not available, incident correlation caching disabled")
            
        # Local cache for incidents when OpenSearch not available
        self.local_incident_cache_path = os.environ.get('INCIDENT_CACHE_FILE', os.path.join('data', 'incidents_cache.json'))
        try:
            os.makedirs(os.path.dirname(self.local_incident_cache_path), exist_ok=True)
        except Exception:
            pass
    
    def check_for_existing_incident(self, alert: Dict) -> Optional[str]:
        """Check Valkey for existing incidents that could correlate with this alert"""
        if not self.redis:
            return None
            
        try:
            # Create correlation key based on alert characteristics
            service = alert.get('service', '').lower()
            severity = alert.get('severity', '').lower()
            alert_type = alert.get('type', '').lower()
            source = alert.get('source', '').lower()
            
            # Look for recent incidents with similar characteristics
            search_patterns = [
                f"incident:*:service:{service}",
                f"incident:*:severity:{severity}",
                f"incident:*:type:{alert_type}",
                f"incident:*:source:{source}"
            ]
            
            # Find incidents from last 15 minutes
            cutoff_time = datetime.utcnow() - timedelta(minutes=15)
            
            for pattern in search_patterns:
                incident_keys = self.redis.keys(pattern)
                for key in incident_keys:
                    incident_data = self.redis.hgetall(key)
                    if incident_data:
                        # Check if incident is recent
                        created_time = datetime.fromisoformat(incident_data.get('created_at', '').rstrip('Z'))
                        if created_time > cutoff_time:
                            # Check for correlation based on similarity
                            if self._are_alerts_similar(alert, json.loads(incident_data.get('representative_alert', '{}'))):
                                incident_id = incident_data.get('incident_id')
                                logger.info(f"Found correlating incident: {incident_id}")
                                return incident_id
                                
        except Exception as e:
            logger.warning(f"Error checking for existing incidents in Valkey: {e}")
            
        return None
    
    def _are_alerts_similar(self, alert1: Dict, alert2: Dict) -> bool:
        """Check if two alerts are similar enough to correlate"""
        # Simple similarity check - can be enhanced with ML models
        similarity_score = 0
        total_checks = 0
        
        # Check service similarity
        if alert1.get('service') == alert2.get('service'):
            similarity_score += 1
        total_checks += 1
        
        # Check severity similarity  
        if alert1.get('severity') == alert2.get('severity'):
            similarity_score += 1
        total_checks += 1
        
        # Check source similarity
        if alert1.get('source') == alert2.get('source'):
            similarity_score += 1
        total_checks += 1
        
        # Check alert type similarity
        if alert1.get('type') == alert2.get('type'):
            similarity_score += 1
        total_checks += 1
        
        # Simple threshold - can be made configurable
        similarity_ratio = similarity_score / total_checks if total_checks > 0 else 0
        return similarity_ratio >= 0.6  # 60% similarity threshold
    
    def add_alert_to_incident(self, alert: Dict, incident_id: str):
        """Add an alert to an existing incident in Valkey"""
        if not self.redis:
            return
            
        try:
            # Add alert to incident's alert list
            alert_key = f"incident:{incident_id}:alerts"
            self.redis.lpush(alert_key, json.dumps(alert))
            
            # Update incident metadata
            incident_key = f"incident:{incident_id}:meta"
            self.redis.hset(incident_key, "last_updated", datetime.utcnow().isoformat() + 'Z')
            self.redis.hincrby(incident_key, "alert_count", 1)
            
            # Set expiration (24 hours)
            self.redis.expire(alert_key, 86400)
            self.redis.expire(incident_key, 86400)
            
            logger.info(f"Added alert to incident {incident_id} in Valkey")
            
        except Exception as e:
            logger.warning(f"Error adding alert to incident in Valkey: {e}")
    
    def get_incident_alerts(self, incident_id: str) -> List[Dict]:
        """Get all alerts for an incident from Valkey"""
        if not self.redis:
            return []
            
        try:
            alert_key = f"incident:{incident_id}:alerts"
            alert_jsons = self.redis.lrange(alert_key, 0, -1)
            
            alerts = []
            for alert_json in alert_jsons:
                try:
                    alerts.append(json.loads(alert_json))
                except json.JSONDecodeError:
                    continue
                    
            return alerts
            
        except Exception as e:
            logger.warning(f"Error getting incident alerts from Valkey: {e}")
            return []
    
    def create_incident_in_valkey(self, incident_id: str, alert: Dict):
        """Create a new incident in Valkey"""
        if not self.redis:
            return
            
        try:
            current_time = datetime.utcnow().isoformat() + 'Z'
            
            # Store incident metadata
            incident_key = f"incident:{incident_id}:meta"
            self.redis.hset(incident_key, {
                "incident_id": incident_id,
                "created_at": current_time,
                "last_updated": current_time,
                "alert_count": 1,
                "status": "open",
                "representative_alert": json.dumps(alert)
            })
            
            # Store first alert
            alert_key = f"incident:{incident_id}:alerts"
            self.redis.lpush(alert_key, json.dumps(alert))
            
            # Create searchable keys for correlation
            service = alert.get('service', '').lower()
            severity = alert.get('severity', '').lower()
            alert_type = alert.get('type', '').lower()
            source = alert.get('source', '').lower()
            
            search_keys = [
                f"incident:{incident_id}:service:{service}",
                f"incident:{incident_id}:severity:{severity}",
                f"incident:{incident_id}:type:{alert_type}",
                f"incident:{incident_id}:source:{source}"
            ]
            
            for search_key in search_keys:
                self.redis.set(search_key, incident_id, ex=86400)  # 24 hour expiration
                
            # Set expiration (24 hours)
            self.redis.expire(incident_key, 86400)
            self.redis.expire(alert_key, 86400)
            
            logger.info(f"Created incident {incident_id} in Valkey")
            
        except Exception as e:
            logger.warning(f"Error creating incident in Valkey: {e}")

    async def send_to_queue(self, message: Dict, queue_type: str, environment: Optional[str] = None) -> Optional[str]:
        """Send a message to the appropriate SQS queue and return MessageId on success."""
        try:
            if not environment:
                environment = self.environment
            
            # Strict environment-specific SQS queue URLs
            if environment == "development":
                queue_url = "https://sqs.ap-southeast-1.amazonaws.com/528104389666/dev-events-core"
            elif environment == "production":
                queue_url = "https://sqs.ap-southeast-1.amazonaws.com/528104389666/prod-events-core"
            else:
                raise ValueError(f"Invalid environment: {environment}. Must be 'production' or 'development'")
            # Assert queue URL matches environment
            if environment == 'development' and 'dev-events-core' not in queue_url:
                raise ValueError(f"SQS queue URL mismatch for development: {queue_url}")
            if environment == 'production' and 'prod-events-core' not in queue_url:
                raise ValueError(f"SQS queue URL mismatch for production: {queue_url}")
            
            # Prepare body as plain JSON - ensure all values are JSON serializable
            body = message if isinstance(message, dict) else {}
            # Ensure environment is included in body for downstream consumers
            try:
                if isinstance(body, dict) and 'environment' not in body:
                    body['environment'] = environment
            except Exception:
                pass
            
            # Ensure all values are properly serializable
            try:
                if queue_type == "incidents" and isinstance(message, dict):
                    # Convert any non-serializable values to strings
                    for k, v in body.items():
                        if isinstance(v, bool):
                            # Ensure booleans are actual booleans, not strings
                            body[k] = bool(v)
                        elif isinstance(v, (int, float)):
                            # Ensure numbers are actual numbers
                            continue
                        elif isinstance(v, dict) and k == "data" and "alerts" in v:
                            # Ensure alert IDs are strings in the alerts array
                            for alert in v.get("alerts", []):
                                if "alert_item_id" in alert:
                                    alert["alert_item_id"] = str(alert["alert_item_id"])
            except Exception as e:
                logger.warning(f"Error preparing message body: {e}")
                # Fallback to raw body on any serialization issue
                body = message if isinstance(message, dict) else {}
            # Ensure message body is valid JSON
            message_body = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
            
            # Log the message for debugging
            logger.debug(f"Sending message to SQS queue {queue_type}: {message_body[:100]}...")
            
            response = self.sqs.send_message(
                QueueUrl=queue_url,
                MessageBody=message_body,
                MessageAttributes={
                    'MessageType': {
                        'DataType': 'String',
                        'StringValue': queue_type
                    },
                    'Environment': {
                        'DataType': 'String',
                        'StringValue': environment
                    }
                }
            )
            msg_id = response.get('MessageId')
            logger.info(f"Successfully sent message to queue {queue_type} with ID: {msg_id}")
            try:
                # Record ack for reporting
                if queue_type in self._sqs_acks:
                    self._sqs_acks[queue_type].append(msg_id)
            except Exception:
                pass
            return msg_id
            
        except Exception as e:
            logger.error(f"Error sending message to queue {queue_type}: {e}")
            return None

    def _index_timeline_event(self, incident_id: str, event: Dict[str, Any]) -> Optional[str]:
        """Append a correlation event onto the incident document in OpenSearch (single doc per incident)."""
        if self.os is None:
            logger.warning("OpenSearch client not initialized; skipping timeline indexing")
            return None
        try:
            now_iso = datetime.utcnow().isoformat() + 'Z'
            update_body = {
                "script": {
                    "lang": "painless",
                    "source": (
                        "if (ctx._source.correlation == null) { ctx._source.correlation = new ArrayList(); } "
                        "ctx._source.correlation.add(params.event); "
                        "ctx._source.updated_at = params.now;"
                    ),
                    "params": {"event": event, "now": now_iso}
                },
                "upsert": {
                    "id": incident_id,
                    "incident_id": incident_id,
                    "doc_kind": "incident",
                    "correlation": [event],
                    "created_at": now_iso,
                    "updated_at": now_iso
                }
            }
            resp = self.os.update(index=self.os_index, id=incident_id, body=update_body, refresh=True)
            logger.info(f"Appended correlation event to incident {incident_id} in OpenSearch")
            return resp.get('_id', incident_id)
        except os_exceptions.OpenSearchException as e:
            logger.error(f"OpenSearch error indexing timeline: {e}")
            return None
        except Exception as e:
            logger.error(f"Error indexing timeline: {e}")
            return None

    def _index_incident_document(self, incident: Dict[str, Any]) -> Optional[str]:
        """Index or upsert the incident document in OpenSearch (doc_kind=incident)."""
        if self.os is None:
            return None
        try:
            body = {"doc_kind": "incident", **incident}
            resp = self.os.index(index=self.os_index, id=incident.get("id"), body=body, refresh=True)
            return resp.get("_id")
        except Exception as e:
            logger.warning(f"Failed to index incident to OpenSearch: {e}")
            return None

    def _fetch_incident_document(self, incident_id: str) -> Optional[Dict[str, Any]]:
        # Try OpenSearch first
        if self.os is not None:
            try:
                resp = self.os.get(index=self.os_index, id=incident_id, ignore=[404])
                if resp and resp.get("found"):
                    return resp.get("_source")
            except Exception as e:
                logger.warning(f"Failed to fetch incident {incident_id} from OpenSearch: {e}")
        # Fallback to local cache
        try:
            if os.path.exists(self.local_incident_cache_path):
                with open(self.local_incident_cache_path, 'r') as f:
                    cache = json.load(f) or []
                for inc in cache:
                    if inc.get('id') == incident_id:
                        return inc
        except Exception as e:
            logger.warning(f"Failed to fetch incident {incident_id} from local cache: {e}")
        return None

    def _build_alert_item(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        alert_service_id, alert_service_name, alert_service_obj = self.safe_get_service_info(alert.get("service", ""))
        alert_service_obj['id'] = alert.get('service_id', '')
        return {
            "alert_name": alert.get("title", ""),
            "status": alert.get("status", "triggered"),
            "source": alert.get("source", ""),
            "service": alert_service_obj,
            "description": alert.get("description", ""),
            "alert_item_id": alert.get("id"),
            "trigger": alert.get("trigger"),
            "created_at": alert.get("createdAt") or (alert.get("parsed_time").isoformat()+"Z" if alert.get("parsed_time") else None),
            "updated_at": alert.get("updatedAt"),
            "sources": alert.get("sources"),
            "policy_names": alert.get("alertPolicyNames"),
            "condition_names": alert.get("alertConditionNames"),
            "impacted_entities": alert.get("impactedEntities")
        }

    async def _update_incident_with_alerts(self, incident_id: str, new_alerts: List[Dict[str, Any]], environment: str) -> Optional[Dict[str, Any]]:
        """Append alerts to an existing incident, promote to correlated, update counters/timestamps, reindex and notify SQS."""
        existing = self._fetch_incident_document(incident_id)
        if not existing:
            logger.warning(f"Existing incident {incident_id} not found in OpenSearch for update")
            return None
        try:
            # Build alert items and deduplicate by alert_item_id
            new_items = [self._build_alert_item(a) for a in new_alerts]
            existing_alerts = (((existing.get("data") or {}).get("alerts")) or [])
            by_id = {str(item.get("alert_item_id")): item for item in existing_alerts if item.get("alert_item_id") is not None}
            for it in new_items:
                key = str(it.get("alert_item_id"))
                if key and key not in by_id:
                    by_id[key] = it
            merged_alerts = list(by_id.values())

            # Compute times
            now_iso = datetime.utcnow().isoformat() + 'Z'
            last_alert_at = existing.get("last_alert_at") or now_iso
            # If new alerts carry times, use the max
            times = []
            for a in new_alerts:
                t = a.get('parsed_time')
                if t:
                    times.append(t)
            if times:
                last_alert_at = max(times).isoformat() + 'Z'

            updated = {**existing}
            updated["is_correlated"] = True
            updated["updated_at"] = now_iso
            updated["last_alert_at"] = last_alert_at
            updated["alert_count"] = len(merged_alerts)
            updated["correlation_method"] = "dbscan"
            data_obj = (updated.get("data") or {})
            data_obj["alerts"] = merged_alerts
            updated["data"] = data_obj

            # Reindex document or persist to cache if OS unavailable
            if not self._index_incident_document(updated):
                try:
                    cache = []
                    if os.path.exists(self.local_incident_cache_path):
                        with open(self.local_incident_cache_path, 'r') as f:
                            cache = json.load(f) or []
                    # replace or append
                    cache = [c for c in cache if c.get('id') != incident_id]
                    cache.append(updated)
                    with open(self.local_incident_cache_path, 'w') as f:
                        json.dump(cache, f)
                except Exception as e:
                    logger.warning(f"Failed to persist updated incident to local cache: {e}")
                        # For updates, only send the new alerts data
            try:
                update_payload = {
                    "messageType": "ALERT_UPDATED",
                    "incident_id": incident_id,
                    "data": {
                        "alerts": [self._build_alert_item(a) for a in new_alerts]
                    }
                }
                msg_id = await self.send_to_queue(update_payload, "incidents", environment)
                if msg_id:
                    logger.info(f"ACK: incident updated (correlated) message_id={msg_id}")
            except Exception as e:
                logger.warning(f"Failed to enqueue update payload: {e}")

            # Index timeline entries for each new alert
            for alert in new_alerts:
                timeline_entry = {
                    "id": str(uuid.uuid4()),
                    "incident_id": incident_id,
                    "type": "CORRELATED",
                    "content": {
                        "alert_title": alert.get('title', ''),
                        "correlation_reason": "Multi-signal correlation (cross-run)",
                        "service": alert.get('service', ''),
                        "source": alert.get('source', '')
                    },
                    "created_at": datetime.utcnow().isoformat() + 'Z',
                    "alert_id": str(alert.get('id', ''))
                }
                self._index_timeline_event(incident_id, timeline_entry)

            return updated
        except Exception as e:
            logger.error(f"Failed to update incident {incident_id} with new alerts: {e}")
            return None
        
        # Initialize sentence transformer for semantic similarity







    
    def _compute_correlation_details(self, base_alert: Dict[str, Any], new_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Compute detailed correlation info between two alerts including confidence and human-readable reason."""
        # Multi-signal score
        score, confidence, signals = self.calculate_multi_signal_correlation(base_alert, new_alert)
        # Time diff minutes
        time1 = base_alert.get('parsed_time')
        time2 = new_alert.get('parsed_time')
        time_diff_min = None
        if time1 and time2:
            time_diff_min = abs((time2 - time1).total_seconds()) / 60.0
        # Build reason
        parts = []
        if signals.get('semantic', {}).get('score') is not None:
            parts.append(f"title similarity {signals['semantic']['score']:.2f}")
        if signals.get('service', {}).get('score'):
            parts.append("same service")
        if signals.get('company', {}).get('score'):
            parts.append("same company")
        if signals.get('source', {}).get('score'):
            parts.append("same source")
        if time_diff_min is not None:
            parts.append(f"within {int(time_diff_min)} min of base alert")
        base_title = base_alert.get('title') or base_alert.get('alert_name') or ''
        new_title = new_alert.get('title') or new_alert.get('alert_name') or ''
        reason = (
            f"'{new_title}' correlated with base alert '{base_title}' via multi-signal agreement: "
            f"{'; '.join(parts)}. Combined correlation score={score:.3f} with confidence={confidence:.2f}."
        )
        return {
            "score": float(score),
            "confidence": float(confidence),
            "signals": signals,
            "reason": reason
        }
    
    def safe_get_service_info(self, service: Any) -> Tuple[str, str, Dict]:
        """Safely extract service information from either string or dict format"""
        try:
            if isinstance(service, str):
                service_str = service.strip()
                service_obj = {
                    'id': '',  # Will be replaced by service_id from alert
                    'name': service_str
                }
                return '', service_str, service_obj
                
            elif isinstance(service, dict):
                service_name = service.get('name', '')
                if not service_name:
                    service_name = service.get('description', '')
                if not service_name:
                    service_name = ''
                
                service_obj = {
                    'id': '',  # Will be replaced by service_id from alert
                    'name': str(service_name).strip()
                }
                
                # Copy any additional fields from original service
                for key, value in service.items():
                    if key not in ['id', 'name']:
                        service_obj[key] = value
                
                return '', str(service_name).strip(), service_obj
            else:
                service_str = str(service) if service is not None else ''
                service_obj = {
                    'id': '',  # Will be replaced by service_id from alert
                    'name': service_str
                }
                return '', service_str, service_obj
        except Exception as e:
            logger.warning(f"Error processing service field: {e}")
            default_service = {
                'id': '',  # Will be replaced by service_id from alert
                'name': 'unknown'
            }
            return '', 'unknown', default_service
    
    def find_company_prefix(self, bucket_name: str, alert: Optional[Dict] = None) -> str:
        """Extract company prefix/slug from bucket name or alert metadata"""
        try:
            # First try to get from alert meta_data
            if alert and isinstance(alert.get('meta_data', {}), dict):
                compslug = alert.get('meta_data', {}).get('compslug')
                if compslug:
                    return compslug.lower()
            
            # Then try to extract from bucket name with strict 12-digit suffix validation
            if bucket_name.startswith("dev-bugraid-"):
                bucket_parts = bucket_name.split('-')
                if len(bucket_parts) >= 4 and bucket_parts[-1].isdigit() and len(bucket_parts[-1]) == 12:
                    company_slug = "-".join(bucket_parts[2:-1])
                    logger.info(f"Extracted company slug '{company_slug}' from dev bucket name: {bucket_name}")
                    return company_slug.lower()
                else:
                    logger.info(f"Dev bucket name {bucket_name} does not have a 12-digit suffix, skipping")
            
            elif bucket_name.startswith("bugraid-"):
                bucket_parts = bucket_name.split('-')
                if len(bucket_parts) >= 3 and bucket_parts[-1].isdigit() and len(bucket_parts[-1]) == 12:
                    company_slug = "-".join(bucket_parts[1:-1])
                    logger.info(f"Extracted company slug '{company_slug}' from production bucket name: {bucket_name}")
                    return company_slug.lower()
                else:
                    logger.info(f"Production bucket name {bucket_name} does not have a 12-digit suffix, skipping")
            
            # Fallback to 'unknown'
            return 'unknown'
        except Exception as e:
            logger.warning(f"Error extracting company prefix: {e}")
            return 'unknown'
    
    async def get_next_counter_value(self, company_id: str, counter_name: str = "incident", environment: str = None) -> int:
        """Get the next counter value from the counters table and increment it"""
        try:
            if not environment:
                environment = self.environment
            
            company_id = str(company_id)
            logger.debug(f"Getting counter value for company_id: {company_id}, counter: {counter_name}, environment: {environment}")
            
            counters_table_env = self.get_table_by_environment("counters", environment)
            counters_table_name = self.get_table_name("counters", environment)
            logger.debug(f"Using counters table: {counters_table_name}")
            
            counter_id = company_id
            logger.debug(f"Looking for counter with ID: {counter_id}")
            
            # Try to get the current counter value
            response = counters_table_env.get_item(Key={'id': counter_id})
            
            if 'Item' in response:
                # Counter exists, increment it
                counter_item = response['Item']
                current_value = int(counter_item.get('value', 0))
                new_value = current_value + 1
                
                logger.debug(f"Counter found with current value: {current_value}, incrementing to {new_value}")
                
                # Update the counter
                counters_table_env.update_item(
                    Key={'id': counter_id},
                    UpdateExpression="SET #val = :new_val, updated_at = :updated_at",
                    ExpressionAttributeNames={'#val': 'value'},
                    ExpressionAttributeValues={
                        ':new_val': new_value,
                        ':updated_at': datetime.now().isoformat()
                    }
                )
                
                logger.info(f"Successfully incremented counter {counter_id} from {current_value} to {new_value} in {environment} environment")
                return new_value
            else:
                # Counter doesn't exist, return default value 1 without creating a new entry
                logger.warning(f"No counter found for company_id {counter_id}, returning default value 1")
                return 1
                
        except Exception as e:
            logger.error(f"Error getting next counter value: {e}")
            return 1  # Default to 1 if there's an error
    
    async def get_next_incident_number(self, bucket_name: str, environment: str = None, alert: Dict = None) -> int:
        """Get the next incident number via Counter API with robust fallback."""
        logger.info(f"Getting next incident number for bucket {bucket_name} in {environment} environment")
        
        if not environment:
            environment = self.environment
        
        if not isinstance(alert, dict) or not alert.get('company_id'):
            raise ValueError("No company_id found in alert payload. Cannot proceed with counter lookup.")
        company_id = str(alert['company_id'])

        # Strict environment-specific API URLs - no environment overrides
        if environment == "production":
            counter_url = 'https://api.bugraid.ai/api/v1/incidents/inc-update/counter/{company_id}'
        elif environment == "development":
            counter_url = 'https://dev-api.bugraid.ai/api/v1/incidents/inc-update/counter/{company_id}'
        else:
            raise ValueError(f"Invalid environment: {environment}. Must be 'production' or 'development'")
        
        logger.info(f"Using counter API URL for environment '{environment}': {counter_url}")

        # Use httpx for async request (GET to fetch, POST to increment if supported)
        try:
            import httpx
            from urllib.parse import urlparse
            async with httpx.AsyncClient(timeout=5) as client:
                # Fetch current counter
                fetch_url = counter_url.format(company_id=company_id)
                # Validate host per environment before calling
                host = urlparse(fetch_url).netloc
                if environment == 'production' and 'api.bugraid.ai' not in host:
                    raise ValueError(f"Counter API host mismatch for production: {host}")
                if environment == 'development' and 'dev-api.bugraid.ai' not in host:
                    raise ValueError(f"Counter API host mismatch for development: {host}")
                resp = await client.get(fetch_url)
                resp.raise_for_status()
                data = resp.json() or {}
                # Expect { data: { company_id, counter } }
                current = None
                if isinstance(data, dict):
                    current = (
                        data.get('data', {}).get('counter')
                        or data.get('counter')
                        or data.get('value')
                    )
                current_val = int(current or 0)

                # Use the exact value returned by the API without incrementing
                next_number = current_val
                logger.info(f"Using GET-only counter approach, using exact value from API: {next_number}")

                logger.info(f"Counter API returned incident number: {next_number}")
                return next_number
        except Exception as e:
            logger.warning(f"Counter API failed ({e}); falling back to in-memory counter per company")
            # Fallback: keep a simple per-company counter in memory for this run
            if not hasattr(self, '_local_counters'):
                self._local_counters = {}
            self._local_counters.setdefault(company_id, 0)
            self._local_counters[company_id] += 1
            return self._local_counters[company_id]
    
    def calculate_alert_severity_score(self, alert: Dict) -> float:
        """Calculate severity score for an alert"""
        try:
            priority_scores = {
                'critical': 5, 'p0': 5, 'p1': 4, 'high': 4,
                'medium': 3, 'p2': 3, 'p3': 2, 'low': 2, 'p4': 1
            }
            
            priority = alert.get('priority', '').lower()
            if not priority:
                priority = alert.get('severity', '').lower()
            
            score = priority_scores.get(priority, 3)
            
            # Adjust based on impact
            impact = alert.get('impact', '').lower()
            if impact in ['critical', 'high']:
                score += 1
            elif impact in ['low']:
                score -= 1
            
            # Adjust based on urgency
            urgency = alert.get('urgency', '').lower()
            if urgency in ['critical', 'high']:
                score += 0.5
            elif urgency in ['low']:
                score -= 0.5
            
            return max(1, min(5, score))
            
        except Exception as e:
            logger.warning(f"Error calculating severity score: {e}")
            return 3
    
    def calculate_semantic_similarity(self, alert1: Dict, alert2: Dict) -> float:
        """Calculate semantic similarity between two alerts using sentence transformers"""
        try:
            if not self.sentence_model:
                return 0.0
            
            text1 = f"{alert1.get('title', '')} {alert1.get('description', '')}"
            text2 = f"{alert2.get('title', '')} {alert2.get('description', '')}"
            
            if not text1.strip() or not text2.strip():
                return 0.0
            
            embeddings = self.sentence_model.encode([text1, text2])
            similarity = cosine_similarity([embeddings[0]], [embeddings[1]])[0][0]
            
            return float(similarity)
            
        except Exception as e:
            logger.warning(f"Error calculating semantic similarity: {e}")
            return 0.0
    
    def calculate_time_proximity_score(self, alert1: Dict, alert2: Dict) -> float:
        """
        Calculate time proximity score between two alerts
        
        Score is highest when alerts are close in time, and decreases linearly as they get further apart.
        Alerts outside the time window (15 minutes by default, max 60 minutes) get a score of 0.
        """
        try:
            time1 = alert1.get('parsed_time')
            time2 = alert2.get('parsed_time')
            
            if not time1 or not time2:
                return 0.0
            
            # Calculate time difference in seconds
            time_diff = abs((time1 - time2).total_seconds())
            
            # Use the configured time window, but cap at 60 minutes max
            max_time_window_minutes = 60  # Maximum time window in minutes
            effective_time_window = min(self.time_window_minutes, max_time_window_minutes)
            max_time_diff = effective_time_window * 60  # Convert to seconds
            
            if time_diff <= max_time_diff:
                # Score decreases linearly with time difference
                score = 1.0 - (time_diff / max_time_diff)
                return max(0.0, score)
            
            # If time difference is greater than the time window, return 0
            return 0.0
            
        except Exception as e:
            logger.warning(f"Error calculating time proximity: {e}")
            return 0.0
    
    def calculate_multi_signal_correlation(self, alert1: Dict, alert2: Dict) -> Tuple[float, float, Dict]:
        """Calculate multi-signal correlation between two alerts"""
        try:
            signals = {}
            
            # 1. Semantic correlation (title + description)
            semantic_score = self.calculate_semantic_similarity(alert1, alert2)
            signals['semantic'] = {
                'score': semantic_score,
                'explanation': f'Text similarity: {semantic_score:.2f}'
            }
            
            # 2. Service correlation
            service1 = str(alert1.get('service', '')).lower()
            service2 = str(alert2.get('service', '')).lower()
            service_score = 1.0 if service1 == service2 and service1 else 0.0
            signals['service'] = {
                'score': service_score,
                'explanation': f'Same service: {service_score > 0}'
            }
            
            # 3. Time proximity
            time_score = self.calculate_time_proximity_score(alert1, alert2)
            signals['time'] = {
                'score': time_score,
                'explanation': f'Time proximity: {time_score:.2f}'
            }
            
            # 4. Company correlation
            company1 = alert1.get('company_id')
            company2 = alert2.get('company_id')
            company_score = 1.0 if company1 == company2 and company1 else 0.0
            signals['company'] = {
                'score': company_score,
                'explanation': f'Same company: {company_score > 0}'
            }
            
            # 5. Source correlation
            source1 = alert1.get('source', '').lower()
            source2 = alert2.get('source', '').lower()
            source_score = 1.0 if source1 == source2 and source1 else 0.0
            signals['source'] = {
                'score': source_score,
                'explanation': f'Same source: {source_score > 0}'
            }
            
            # Calculate weighted total score
            weights = {
                'semantic': 0.3,
                'service': 0.25,
                'time': 0.2,
                'company': 0.15,
                'source': 0.1
            }
            
            total_score = sum(signals[signal]['score'] * weights[signal] for signal in weights)
            
            # Calculate confidence based on how many signals are active
            active_signals = sum(1 for signal in signals.values() if signal['score'] > 0.1)
            confidence = active_signals / len(signals)
            
            return total_score, confidence, signals
            
        except Exception as e:
            logger.warning(f"Error calculating multi-signal correlation: {e}")
            return 0.0, 0.0, {}
    
    def apply_sliding_time_window(self, alerts: List[Dict]) -> List[List[Dict]]:
        """
        Apply sliding time window to group alerts
        
        Groups alerts that occur within the configured time window (default 15 minutes).
        The maximum time window is capped at 60 minutes.
        """
        if not alerts:
            return []
        
        # Sort alerts by timestamp
        sorted_alerts = sorted(alerts, key=lambda x: x.get('parsed_time', datetime.min))
        
        # Use the configured time window, but cap at 60 minutes max
        max_time_window_minutes = 60  # Maximum time window in minutes
        effective_time_window = min(self.time_window_minutes, max_time_window_minutes)
        
        logger.info(f"Using time window of {effective_time_window} minutes for alert grouping")
        
        time_windows = []
        current_window = []
        window_start = None
        
        for alert in sorted_alerts:
            alert_time = alert.get('parsed_time')
            if not alert_time:
                continue
            
            if not current_window:
                # Start new window
                current_window = [alert]
                window_start = alert_time
            else:
                # Check if alert fits in current window
                time_diff = (alert_time - window_start).total_seconds() / 60  # Convert to minutes
                
                if time_diff <= effective_time_window:
                    current_window.append(alert)
                else:
                    # Close current window and start new one
                    if len(current_window) > 0:
                        time_windows.append(current_window)
                    current_window = [alert]
                    window_start = alert_time
        
        # Add the last window
        if current_window:
            time_windows.append(current_window)
        
        logger.info(f"Time windows formed: {len(time_windows)} using {effective_time_window} minute window")
        return time_windows
    
    def advanced_correlation_analysis(self, alerts: List[Dict]) -> List[List[int]]:
        """Perform advanced correlation analysis using DBSCAN clustering"""
        if len(alerts) < 2:
            return [[i] for i in range(len(alerts))]
        
        try:
            # Create correlation matrix
            n_alerts = len(alerts)
            correlation_matrix = np.zeros((n_alerts, n_alerts))
            
            logger.info(f"\n🔍 Calculating multi-signal correlations for {n_alerts} alerts:")
        
            for i in range(n_alerts):
                for j in range(n_alerts):
                    if i != j:
                        total_score, confidence, signals = self.calculate_multi_signal_correlation(
                            alerts[i], alerts[j]
                        )
                        correlation_matrix[i][j] = total_score
                        if total_score > self.similarity_threshold:
                            logger.info(f"      Alert {i+1} <-> Alert {j+1}: score={total_score:.3f}, confidence={confidence:.3f}")
                            for signal_name, signal_data in signals.items():
                                if signal_data['score'] > 0.1:
                                    logger.info(f"        {signal_name}: {signal_data['score']:.3f} ({signal_data['explanation']})")
            
            # Convert correlation matrix to distance matrix and fix diagonal to 0
            distance_matrix = 1 - correlation_matrix
            np.fill_diagonal(distance_matrix, 0.0)
        
            # Apply DBSCAN clustering
            dbscan = DBSCAN(eps=self.eps, min_samples=self.min_samples, metric='precomputed')
            cluster_labels = dbscan.fit_predict(distance_matrix)
            
            # Group alerts by cluster
            clusters = defaultdict(list)
            for i, label in enumerate(cluster_labels):
                clusters[label].append(i)
            
            # Convert to list of lists, handling noise points (-1) as individual clusters
            result_clusters = []
            for label, indices in clusters.items():
                if label == -1:
                    # Noise points become individual clusters
                    for idx in indices:
                        result_clusters.append([idx])
                else:
                    result_clusters.append(indices)
            
            logger.info(f"DBSCAN clustering found {len(result_clusters)} clusters")
            return result_clusters
            
        except Exception as e:
            logger.error(f"Error in advanced correlation analysis: {e}")
            # Fallback to individual clusters
            return [[i] for i in range(len(alerts))]
    
    async def enhanced_incident_matching(self, title: str, service: str, company_id: str, 
                                       group_alerts: List[Dict], environment: str) -> Optional[str]:
        """Match alerts with existing incidents within a time window using OpenSearch lookback."""
        try:
            logger.info(f"\n🔍 Searching for existing incidents to match with:")
            logger.info(f"   Title: {title}")
            logger.info(f"   Service: {service}")
            logger.info(f"   Company: {company_id}")
            all_items = []

            # Query OpenSearch for recent incidents
            if company_id:
                try:
                    max_time_window_minutes = 60
                    time_window_minutes = min(self.time_window_minutes, max_time_window_minutes)
                    cutoff_time = (datetime.utcnow() - timedelta(minutes=time_window_minutes)).isoformat() + 'Z'
                    # Prefer exact service_id if we can derive it from alerts
                    service_id = None
                    for a in group_alerts:
                        if a.get('service_id'):
                            service_id = a['service_id']
                            break
                    service_str = (service or '').lower()
                    # Try OpenSearch first
                    if self.os is not None:
                        try:
                            must_filters = [
                                {"term": {"doc_kind": "incident"}},
                                {"term": {"company_id": company_id}},
                                {"range": {"last_alert_at": {"gte": cutoff_time}}}
                            ]
                            if service_id:
                                must_filters.append({"term": {"service_id": service_id}})
                            query = {"bool": {"must": must_filters}}
                            resp = self.os.search(index=self.os_index, body={
                                "size": 25,
                                "query": query,
                                "sort": [{"last_alert_at": {"order": "desc"}}]
                            })
                            hits = resp.get('hits', {}).get('hits', [])
                            for h in hits:
                                src = h.get('_source') or {}
                                all_items.append(src)
                        except Exception as e:
                            logger.warning(f"OpenSearch incident lookback failed: {e}")
                    # Fallback to local cache if OS not configured or failed
                    if not all_items and os.path.exists(self.local_incident_cache_path):
                        try:
                            with open(self.local_incident_cache_path, 'r') as f:
                                cache = json.load(f) or []
                            for inc in cache:
                                if inc.get('company_id') != company_id:
                                    continue
                                if service_id and inc.get('service_id') != service_id:
                                    continue
                                # Filter cutoff
                                la = inc.get('last_alert_at') or inc.get('created_at')
                                if la and la >= cutoff_time:
                                    all_items.append(inc)
                        except Exception as e:
                            logger.warning(f"Local cache incident lookback failed: {e}")
                except Exception as e:
                    logger.warning(f"OpenSearch incident lookback failed: {e}")
            
            # Calculate time window for matching (default 15 minutes, max 60 minutes)
            max_time_window_minutes = 60  # Maximum time window in minutes
            time_window_minutes = min(self.time_window_minutes, max_time_window_minutes)
            
            # Get current time and calculate cutoff time
            current_time = datetime.utcnow()
            cutoff_time = current_time - timedelta(minutes=time_window_minutes)
            cutoff_time_str = cutoff_time.isoformat() + 'Z'
            
            logger.info(f"   Time window: {time_window_minutes} minutes (incidents after {cutoff_time_str})")
            
            logger.info(f"Found {len(all_items)} recent existing incidents for company {company_id} within the time window")
            
            if not all_items:
                return None
            
            # Score incidents for matching
            best_match = None
            best_score = 0
            
            for incident in all_items:
                incident_id = incident.get('id', '')
                incident_title = (incident.get('title') or '').lower()
                incident_service_id = (incident.get('service_id') or '').lower()
                incident_service_name = ((incident.get('service') or {}).get('name') or '').lower()
                incident_created_at = incident.get('created_at', '')
                
                # Skip incidents outside the time window (additional safety check)
                if incident_created_at:
                    try:
                        incident_time = datetime.fromisoformat(incident_created_at.rstrip('Z'))
                        if incident_time < cutoff_time:
                            logger.debug(f"Skipping incident {incident_id} - outside time window")
                            continue
                    except (ValueError, TypeError):
                        # If we can't parse the time, still include the incident
                        pass
                
                # Calculate title similarity
                title_lower = title.lower()
                title_similarity = 0
                if incident_title and title_lower:
                    # Simple word overlap scoring
                    title_words = set(title_lower.split())
                    incident_words = set(incident_title.split())
                    if title_words and incident_words:
                        common_words = title_words.intersection(incident_words)
                        title_similarity = len(common_words) / max(len(title_words), len(incident_words))
                
                # Service similarity (match by id or by name)
                svc_name = (service or '').lower()
                service_similarity = 0.0
                if service_id and incident_service_id and incident_service_id == service_id:
                    service_similarity = 1.0
                elif svc_name and incident_service_name and (
                    svc_name == incident_service_name or svc_name in incident_service_name or incident_service_name in svc_name
                ):
                    service_similarity = 1.0
                
                # Calculate total similarity
                total_similarity = (title_similarity * 0.7) + (service_similarity * 0.3)
                
                if total_similarity > best_score and total_similarity > 0.5:  # Threshold for matching
                    best_match = incident_id
                    best_score = total_similarity
                    logger.info(f"   Match candidate: {incident_id} (score: {total_similarity:.2f}, created: {incident_created_at})")
            
            if best_match:
                logger.info(f"✅ Found matching incident: {best_match} (score: {best_score:.2f})")
            
            return best_match
            
        except Exception as e:
            logger.error(f"Error in incident matching: {e}")
            return None
    
    async def save_incident(self, group_alerts: List[Dict], bucket_name: str, environment: str) -> str:
        """Create a new incident from correlated alerts"""
        try:
            # Get company_id from alert payload
            company_id = group_alerts[0].get('company_id')
            if not company_id:
                raise ValueError("No company_id found in alert payload. Cannot create incident.")
            
            # Get company slug
            company_slug = self.find_company_prefix(bucket_name, group_alerts[0])
            
            # Get the next available incident number
            logger.info(f"Getting next incident number for company_id {company_id} in {environment} environment")
            new_incident_number = await self.get_next_incident_number(bucket_name, environment, group_alerts[0])
            incident_id = f"{company_slug}-INC-{new_incident_number}"
            logger.info(f"Created incident ID: {incident_id} with number {new_incident_number} for company_id {company_id}")
            
            title = group_alerts[0].get('title', '')
            
            # Always use service_id directly from the alert
            service_id = group_alerts[0].get('service_id', '')
            
            # Get service name and create a service object
            _, service_name, service_obj = self.safe_get_service_info(group_alerts[0].get('service', ''))
            
            # Always set the service ID from the alert payload
            service_obj['id'] = service_id
            
            # If service name is not available, try to get it from other sources
            if not service_name and isinstance(group_alerts[0].get('service', ''), dict):
                if 'name' in group_alerts[0]['service']:
                    service_name = group_alerts[0]['service']['name']
                    service_obj['name'] = service_name
            
            logger.debug(f"Using service ID: {service_id}, service name: {service_name}")
            
            source = group_alerts[0].get('source', '')
            description = group_alerts[0].get('description', '')
            
            # Calculate priority
            priority_score = self.calculate_alert_severity_score(group_alerts[0])
            
            if priority_score >= 4:
                priority = "critical"
                urgency = "high"
            elif priority_score >= 3:
                priority = "high"
                urgency = "medium"
            else:
                priority = "medium"
                urgency = "low"
            
            # Calculate time range
            alert_times = []
            for alert in group_alerts:
                parsed_time = alert.get('parsed_time')
                if parsed_time:
                    if isinstance(parsed_time, str):
                        try:
                            parsed_time = datetime.fromisoformat(parsed_time.rstrip('Z'))
                        except Exception:
                            parsed_time = datetime.utcnow()
                    alert_times.append(parsed_time)
            first_alert_time = min(alert_times) if alert_times else datetime.utcnow()
            last_alert_time = max(alert_times) if alert_times else datetime.utcnow()
            
            # Determine primary candidate alert (highest priority, then earliest time)
            def _priority_rank(alert: Dict) -> int:
                pr = (alert.get('priority') or alert.get('severity') or '').lower()
                mapping = {'p0':5,'critical':5,'p1':4,'high':4,'p2':3,'medium':3,'p3':2,'low':2,'p4':1}
                return mapping.get(pr, 3)
            def _get_alert_time(alert):
                parsed_time = alert.get('parsed_time', datetime.utcnow())
                if isinstance(parsed_time, str):
                    try:
                        return datetime.fromisoformat(parsed_time.rstrip('Z'))
                    except Exception:
                        return datetime.utcnow()
                return parsed_time
            
            sorted_alerts = sorted(
                group_alerts,
                key=lambda a: (-_priority_rank(a), _get_alert_time(a))
            )
            primary_alert = sorted_alerts[0]
            
            # Build alerts structure
            alerts_struct = []
            for alert in group_alerts:
                alert_service_id, alert_service_name, alert_service_obj = self.safe_get_service_info(alert.get("service", ""))
                alert_service_obj['id'] = alert.get('service_id', '')
                
                alert_item = {
                    "alert_name": alert.get("title", ""),
                    "status": alert.get("status", "firing"),
                    "source": alert.get("source", ""),
                    "service": alert_service_obj,
                    "description": alert.get("description", ""),
                    "alert_item_id": alert.get("id")
                }
                alerts_struct.append(alert_item)
            
            # Create incident record
            incident = {
                "id": incident_id,
                "incident_id": incident_id,
                "title": title,
                "service": service_obj,
                "service_id": service_obj.get('id', service_id),
                "source": source,
                "description": description,
                "priority": priority,
                "urgency": urgency,
                "priority_score": int(priority_score),
                "primary_alert_id": primary_alert.get('id'),
                "primary_alert_name": primary_alert.get('title'),
                "company_id": group_alerts[0].get('company_id', ''),
                "bucket_name": bucket_name,
                "status": "triggered",
                "is_correlated": True,
                "created_at": first_alert_time.isoformat() + 'Z',
                "updated_at": last_alert_time.isoformat() + 'Z',
                "first_alert_at": first_alert_time.isoformat() + 'Z',
                "last_alert_at": last_alert_time.isoformat() + 'Z',
                "alert_count": len(group_alerts),
                "correlation_method": "dbscan",
                "environment": environment,
                "messageType": "ALERT_UPDATED",
                "data": {
                    "alerts": alerts_struct
                }
            }
            
            # For new correlated incidents, send full incident data with ALERT_CREATED
            incident["messageType"] = "ALERT_CREATED"  # Override to ALERT_CREATED for new incidents
            incident_msg_id = await self.send_to_queue(incident, "incidents", environment)
            if incident_msg_id:
                logger.info(f"ACK: incident queued message_id={incident_msg_id} (correlated)")
            logger.info(f"Created new incident {incident_id} with {len(group_alerts)} alerts (priority: {priority}) in {environment} environment.")
            
            # Trigger log fetcher lambda for the new incident
            await self._trigger_log_fetcher(incident_id, environment)
            
            # Index incident into OpenSearch for future cross-run correlation or persist locally
            if not self._index_incident_document(incident):
                try:
                    # append to local cache
                    cache = []
                    if os.path.exists(self.local_incident_cache_path):
                        with open(self.local_incident_cache_path, 'r') as f:
                            cache = json.load(f) or []
                    cache = [c for c in cache if c.get('id') != incident_id]
                    cache.append(incident)
                    with open(self.local_incident_cache_path, 'w') as f:
                        json.dump(cache, f)
                except Exception as e:
                    logger.warning(f"Failed to persist incident to local cache: {e}")
            
            # Store timeline entries in OpenSearch (do not send to SQS)
            for alert in group_alerts:
                timeline_entry = {
                    "id": str(uuid.uuid4()),
                    "incident_id": incident_id,
                    "type": "CORRELATED",
                    "content": {
                        "alert_title": alert.get('title', ''),
                        "service": alert.get('service', ''),
                        "source": alert.get('source', '')
                    },
                    "created_at": datetime.utcnow().isoformat() + 'Z',
                    "alert_id": str(alert.get('id', ''))
                }
                # attach detailed correlation info
                try:
                    details = self._compute_correlation_details(primary_alert, alert)
                    timeline_entry["content"]["correlation_reason"] = details.get("reason")
                    timeline_entry["content"]["correlation_score"] = details.get("score")
                    timeline_entry["content"]["correlation_confidence"] = details.get("confidence")
                    timeline_entry["content"]["correlation_signals"] = details.get("signals")
                except Exception:
                    pass
                self._index_timeline_event(incident_id, timeline_entry)
            
            # Update alerts with incident reference
            for alert in group_alerts:
                alert['correlated_incident_id'] = incident_id
            
            return incident_id
            
        except Exception as e:
            logger.error(f"Error creating incident: {e}")
            raise
    
    async def save_single_incident(self, alert: Dict, bucket_name: str, environment: str) -> str:
        """Create an incident for a single uncorrelated alert"""
        try:
            # Get company_id from alert payload
            company_id = alert.get('company_id')
            if not company_id:
                raise ValueError("No company_id found in alert payload. Cannot create incident.")
            
            # Get company slug
            company_slug = self.find_company_prefix(bucket_name, alert)
            
            # Get the next available incident number
            logger.info(f"Getting next incident number for company_id {company_id} in {environment} environment for single incident")
            new_incident_number = await self.get_next_incident_number(bucket_name, environment, alert)
            incident_id = f"{company_slug}-INC-{new_incident_number}"
            logger.info(f"Created single incident ID: {incident_id} with number {new_incident_number} for company_id {company_id}")
            
            title = alert.get('title', '')
            
            # Always use service_id directly from the alert
            service_id = alert.get('service_id', '')
            
            # Get service name and create a service object
            _, service_name, service_obj = self.safe_get_service_info(alert.get('service', ''))
            
            # Always set the service ID from the alert payload
            service_obj['id'] = service_id
            
            # If service name is not available, try to get it from other sources
            if not service_name and isinstance(alert.get('service', ''), dict):
                if 'name' in alert['service']:
                    service_name = alert['service']['name']
                    service_obj['name'] = service_name
            
            logger.info(f"Using service ID: {service_id}, service name: {service_name}")
            
            source = alert.get('source', '')
            description = alert.get('description', '')
            
            # Calculate priority
            priority_score = self.calculate_alert_severity_score(alert)
            
            if priority_score >= 4:
                priority = "critical"
                urgency = "high"
            elif priority_score >= 3:
                priority = "high"
                urgency = "medium"
            else:
                priority = "medium"
                urgency = "low"
            
            # Handle parsed_time being either datetime or string
            alert_time = alert.get('parsed_time', datetime.utcnow())
            if isinstance(alert_time, str):
                try:
                    # Parse ISO format timestamp
                    alert_time = datetime.fromisoformat(alert_time.rstrip('Z'))
                except Exception:
                    alert_time = datetime.utcnow()
            
            # Create incident record
            incident = {
                "id": incident_id,
                "incident_id": incident_id,
                "title": title,
                "service": service_obj,
                "service_id": service_obj.get('id', service_id),
                "source": source,
                "description": description,
                "priority": priority,
                "urgency": urgency,
                "priority_score": int(priority_score),
                "primary_alert_id": alert.get('id'),
                "primary_alert_name": alert.get('title'),
                "company_id": alert.get('company_id', ''),
                "bucket_name": bucket_name,
                "status": "triggered",
                "is_correlated": False,
                "created_at": alert_time.isoformat() + 'Z',
                "updated_at": alert_time.isoformat() + 'Z',
                "first_alert_at": alert_time.isoformat() + 'Z',
                "last_alert_at": alert_time.isoformat() + 'Z',
                "alert_count": 1,
                "correlation_method": "single_alert",
                "environment": environment,
                "messageType": "ALERT_CREATED"
            }
            
            # Send incident to SQS using existing save_single_incident function
            incident_msg_id = await self.send_to_queue(incident, "incidents", environment)
            if incident_msg_id:
                logger.info(f"ACK: incident queued message_id={incident_msg_id} (single)")
            logger.info(f"Created new single incident {incident_id} for alert {alert.get('id')} (priority: {priority}) in {environment} environment.")
            
            # Trigger log fetcher lambda for the new incident
            await self._trigger_log_fetcher(incident_id, environment)

            # Index incident into OpenSearch for future cross-run correlation or persist locally
            if not self._index_incident_document(incident):
                try:
                    cache = []
                    if os.path.exists(self.local_incident_cache_path):
                        with open(self.local_incident_cache_path, 'r') as f:
                            cache = json.load(f) or []
                    cache = [c for c in cache if c.get('id') != incident_id]
                    cache.append(incident)
                    with open(self.local_incident_cache_path, 'w') as f:
                        json.dump(cache, f)
                except Exception as e:
                    logger.warning(f"Failed to persist incident to local cache: {e}")
            
            # Update alert with incident reference
            alert['correlated_incident_id'] = incident_id
            
            return incident_id
            
        except Exception as e:
            logger.error(f"Error creating single incident: {e}")
            raise
    
    async def correlate_events(self, alerts: List[Dict], environment: str = None) -> Tuple[List[str], List[str], Dict]:
        """
        Main method to correlate events and create incidents
        
        Args:
            alerts: List of alert dictionaries
            environment: Environment (development/production)
            
        Returns:
            Tuple of (correlated_incident_ids, single_incident_ids, correlation_stats)
        """
        if not environment:
            environment = self.environment
        
        logger.info(f"Starting event correlation on {len(alerts)} alerts...")
        
        if not alerts:
            return [], [], {"total_alerts": 0, "correlated_incidents": 0, "single_incidents": 0}
        
        # Apply sliding time window
        time_windows = self.apply_sliding_time_window(alerts)
        
        correlated_incident_ids = []
        single_incident_ids = []
        total_correlated_incidents = 0
        total_single_incidents = 0
        
        # Process each time window
        for window_idx, window_alerts in enumerate(time_windows):
            logger.info(f"Processing window {window_idx + 1} with {len(window_alerts)} alerts")
            
            if len(window_alerts) == 1:
                # Single alert - create single incident
                alert = window_alerts[0]
                bucket_name = alert.get('bucket_name', '')
                
                # Check for existing incidents first
                existing_incident = await self.enhanced_incident_matching(
                    alert.get('title', ''),
                    alert.get('service', ''),
                    alert.get('company_id', ''),
                    [alert],
                    environment
                )
                
                if existing_incident:
                    logger.info(f"Alert {alert.get('id')} matched to existing incident {existing_incident}")
                    alert['correlated_incident_id'] = existing_incident
                    # Promote/update existing incident with this alert
                    updated = await self._update_incident_with_alerts(existing_incident, [alert], environment)
                    if updated:
                        correlated_incident_ids.append(existing_incident)
                        total_correlated_incidents += 1
                        # Record correlation entry for this alert
                        try:
                            base = alert  # single alert match: base is the same alert in absence of previous set; reason still computed vs itself
                            entry = {
                                "id": str(uuid.uuid4()),
                                "incident_id": existing_incident,
                                "type": "CORRELATED",
                                "content": {
                                    "alert_title": alert.get('title', ''),
                                    "service": alert.get('service', ''),
                                    "source": alert.get('source', '')
                                },
                                "created_at": datetime.utcnow().isoformat() + 'Z',
                                "alert_id": str(alert.get('id', ''))
                            }
                            details = self._compute_correlation_details(base, alert)
                            entry["content"]["correlation_reason"] = details.get("reason")
                            entry["content"]["correlation_score"] = details.get("score")
                            entry["content"]["correlation_confidence"] = details.get("confidence")
                            entry["content"]["correlation_signals"] = details.get("signals")
                            self._index_timeline_event(existing_incident, entry)
                        except Exception:
                            pass
                else:
                    # Create new single incident
                    incident_id = await self.save_single_incident(alert, bucket_name, environment)
                    single_incident_ids.append(incident_id)
                    total_single_incidents += 1
                    logger.info(f"Created single incident {incident_id} for alert {alert.get('id')}")
            
            else:
                # Multiple alerts - perform correlation analysis
                clusters = self.advanced_correlation_analysis(window_alerts)
                
                logger.info(f"Found {len(clusters)} correlation clusters in window {window_idx + 1}")
                
                for cluster_idx, cluster_indices in enumerate(clusters):
                    cluster_alerts = [window_alerts[i] for i in cluster_indices]
                    
                    if len(cluster_alerts) == 1:
                        # Single alert cluster - create single incident
                        alert = cluster_alerts[0]
                        bucket_name = alert.get('bucket_name', '')
                        
                        # Check for existing incidents first
                        existing_incident = await self.enhanced_incident_matching(
                            alert.get('title', ''),
                            alert.get('service', ''),
                            alert.get('company_id', ''),
                            [alert],
                            environment
                        )
                        
                        if existing_incident:
                            logger.info(f"Alert {alert.get('id')} matched to existing incident {existing_incident}")
                            alert['correlated_incident_id'] = existing_incident
                        else:
                            incident_id = await self.save_single_incident(alert, bucket_name, environment)
                            single_incident_ids.append(incident_id)
                            total_single_incidents += 1
                            logger.info(f"Created single incident {incident_id} for alert {alert.get('id')}")
                    
                    else:
                        # Multiple alerts in cluster - create correlated incident
                        bucket_name = cluster_alerts[0].get('bucket_name', '')
                        
                        # Check for existing incidents first
                        existing_incident = await self.enhanced_incident_matching(
                            cluster_alerts[0].get('title', ''),
                            cluster_alerts[0].get('service', ''),
                            cluster_alerts[0].get('company_id', ''),
                            cluster_alerts,
                            environment
                        )
                        
                        if existing_incident:
                            logger.info(f"Cluster {cluster_idx + 1} matched to existing incident {existing_incident}")
                            for alert in cluster_alerts:
                                alert['correlated_incident_id'] = existing_incident
                            # Promote/update existing incident with these alerts
                            updated = await self._update_incident_with_alerts(existing_incident, cluster_alerts, environment)
                            if updated:
                                correlated_incident_ids.append(existing_incident)
                                total_correlated_incidents += 1
                                # Record correlation entries for each alert
                                try:
                                    base = cluster_alerts[0]
                                    for a in cluster_alerts:
                                        entry = {
                                            "id": str(uuid.uuid4()),
                                            "incident_id": existing_incident,
                                            "type": "CORRELATED",
                                            "content": {
                                                "alert_title": a.get('title', ''),
                                                "service": a.get('service', ''),
                                                "source": a.get('source', '')
                                            },
                                            "created_at": datetime.utcnow().isoformat() + 'Z',
                                            "alert_id": str(a.get('id', ''))
                                        }
                                        details = self._compute_correlation_details(base, a)
                                        entry["content"]["correlation_reason"] = details.get("reason")
                                        entry["content"]["correlation_score"] = details.get("score")
                                        entry["content"]["correlation_confidence"] = details.get("confidence")
                                        entry["content"]["correlation_signals"] = details.get("signals")
                                        self._index_timeline_event(existing_incident, entry)
                                except Exception:
                                    pass
                        else:
                            incident_id = await self.save_incident(cluster_alerts, bucket_name, environment)
                            correlated_incident_ids.append(incident_id)
                            total_correlated_incidents += 1
                            logger.info(f"Created correlated incident {incident_id} with {len(cluster_alerts)} alerts")
        
        # Create correlation stats
        correlation_stats = {
            "total_alerts": len(alerts),
            "time_windows": len(time_windows),
            "correlated_incidents": total_correlated_incidents,
            "single_incidents": total_single_incidents,
            "total_incidents": total_correlated_incidents + total_single_incidents
        }
        
        logger.info(f"EVENT CORRELATION SUMMARY")
        logger.info(f"Total alerts processed:       {len(alerts)}")
        logger.info(f"Time windows formed:          {len(time_windows)}")
        logger.info(f"Correlated incidents:         {total_correlated_incidents}")
        logger.info(f"Single incidents:             {total_single_incidents}")
        logger.info(f"Total incidents created:      {total_correlated_incidents + total_single_incidents}")
        
        return correlated_incident_ids, single_incident_ids, correlation_stats

    async def _trigger_log_fetcher(self, incident_id: str, environment: str):
        """Trigger the log fetcher lambda for a new incident."""
        try:
            # Determine the correct Lambda function name based on environment
            if environment == "production":
                function_name = "bugraid-log-fetcher-prod"
            else:
                function_name = "bugraid-log-fetcher-dev"
            
            # Prepare the payload for the log fetcher
            payload = {
                "incident_ids": [incident_id],  # Changed to match expected format
                "environment": environment,
                "trigger_source": "correlation_agent",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            
            logger.info(f"Triggering log fetcher lambda {function_name} for incident {incident_id}")
            logger.info(f"Payload: {json.dumps(payload)}")
            
            # Invoke the Lambda function asynchronously
            response = self.lambda_client.invoke(
                FunctionName=function_name,
                InvocationType='Event',  # Asynchronous invocation
                Payload=json.dumps(payload)
            )
            
            logger.info(f"Lambda response: {response}")
            
            if response.get('StatusCode') == 202:
                logger.info(f"Successfully triggered log fetcher for incident {incident_id}")
            else:
                logger.warning(f"Unexpected response from log fetcher lambda: {response}")
                
        except Exception as e:
            logger.error(f"Error triggering log fetcher for incident {incident_id}: {str(e)}")
            logger.error(f"Exception details: {str(type(e))}")
            # Don't raise the exception as this shouldn't block incident creation

# Example usage and testing
async def main(state=None):
    """
    Production-ready entry point for EventCorrelationAgent
    
    Args:
        state: Optional state parameter (e.g., 'production', 'development')
    """
    logger.info(f"Starting EventCorrelationAgent in state: {state}")
    
    # STRICT: Use only the ENVIRONMENT variable - no overrides or fallbacks
    environment = os.environ.get('ENVIRONMENT')
    if not environment:
        raise ValueError("ENVIRONMENT variable must be set to either 'production' or 'development'")
    environment = environment.strip().lower()
    if environment not in ("production", "development"):
        raise ValueError(f"Invalid ENVIRONMENT value: {environment}. Must be 'production' or 'development'")
    
    # Configure based on state
    config = {}
    
    # Check if state is a dictionary with configuration
    if isinstance(state, dict):
        config = state.get('config', {})
        # DO NOT override environment from config - use only ENVIRONMENT variable
        # Prefer noise-reduced alerts if present
        alerts = state.get('filtered_alerts') or state.get('alerts', [])
    else:
        # Handle string state parameter (legacy mode) - but still use ENVIRONMENT variable
        config = {
            "time_window_minutes": 15,
            "similarity_threshold": 0.3,
            "min_samples": 2,
            "eps": 0.5
        }
    
        # Get alerts from file
        alerts = []
        alerts_file = os.environ.get("CORRELATION_ALERTS_FILE")
        if alerts_file and os.path.exists(alerts_file):
            logger.info(f"Loading alerts from file: {alerts_file}")
            with open(alerts_file, 'r') as f:
                alerts = json.load(f)
        
    agent = EventCorrelationAgent(config=config, state=state)
    
    try:
        if not alerts:
            logger.warning("No alerts found for correlation. Exiting.")
            return {
                "correlated_incidents": [],
                "single_incidents": [],
                "correlation_stats": {
                    "total_alerts": 0,
                    "time_windows": 0,
                    "correlated_incidents": 0,
                    "single_incidents": 0,
                    "total_incidents": 0
                }
            }
        
        logger.info(f"Correlating {len(alerts)} alerts in {environment} environment")
        
        # Check if we're using sample data or mock DB
        use_sample_data = config.get('alert_ingestion', {}).get('use_sample_data', False)
        use_mock_db = config.get('aws', {}).get('use_mock_db', False)
        
        if use_sample_data or use_mock_db:
            # For sample data, create simple incidents without DB interaction
            correlated_incidents = []
            single_incidents = []
            
            # Group alerts by service
            service_groups = {}
            for alert in alerts:
                service_id = alert.get('service', {}).get('id', 'unknown')
                if service_id not in service_groups:
                    service_groups[service_id] = []
                service_groups[service_id].append(alert)
            
            # Create incidents for each service group
            for service_id, service_alerts in service_groups.items():
                if len(service_alerts) > 1:
                    # Create a correlated incident
                    incident_id = f"bugraid-INC-{uuid.uuid4().hex[:8]}"
                    correlated_incidents.append(incident_id)
                    
                    # Assign incident ID to alerts
                    for alert in service_alerts:
                        alert['correlated_incident_id'] = incident_id
                else:
                    # Create a single incident
                    for alert in service_alerts:
                        incident_id = f"bugraid-INC-{uuid.uuid4().hex[:8]}"
                        single_incidents.append(incident_id)
                        alert['correlated_incident_id'] = incident_id
            
            # Create correlation stats
            stats = {
                "total_alerts": len(alerts),
                "time_windows": len(service_groups),
                "correlated_incidents": len(correlated_incidents),
                "single_incidents": len(single_incidents),
                "total_incidents": len(correlated_incidents) + len(single_incidents)
            }
            
            logger.info(f"EVENT CORRELATION SUMMARY")
            logger.info(f"Total alerts processed:       {len(alerts)}")
            logger.info(f"Time windows formed:          {len(service_groups)}")
            logger.info(f"Correlated incidents:         {len(correlated_incidents)}")
            logger.info(f"Single incidents:             {len(single_incidents)}")
            logger.info(f"Total incidents created:      {len(correlated_incidents) + len(single_incidents)}")
            
            return {
                "correlated_incidents": correlated_incidents,
                "single_incidents": single_incidents,
                "correlation_stats": stats
            }
        else:
            # Use the full correlation logic for real data
            correlated_ids, single_ids, stats = await agent.correlate_events(alerts, environment)
        
        # Save results if output file is specified
        output_file = os.environ.get("CORRELATION_OUTPUT_FILE")
        if output_file:
            with open(output_file, 'w') as f:
                json.dump({
                    "correlated_incidents": correlated_ids,
                    "single_incidents": single_ids,
                    "stats": stats
                }, f, indent=2)
            logger.info(f"Saved correlation results to {output_file}")
        
        return {
            "correlated_incidents": correlated_ids,
            "single_incidents": single_ids,
            "correlation_stats": stats
        }
    except Exception as e:
        logger.error(f"Error in event correlation: {e}")
        return {
            "correlated_incidents": [],
            "single_incidents": [],
            "correlation_stats": {
                "total_alerts": len(alerts),
                "time_windows": 0,
                "correlated_incidents": 0,
                "single_incidents": 0,
                "total_incidents": 0,
                "error": str(e)
            }
        }

# Initialize service (will be created when needed)
correlation_service = None

def get_correlation_service():
    """Get or create correlation service instance"""
    global correlation_service
    if correlation_service is None:
        correlation_service = EventCorrelationAgent()
    return correlation_service

# LangGraph workflow definition
async def correlation_node(state: WorkflowState) -> WorkflowState:
    """Node to correlate alerts and create incidents"""
    try:
        alerts = state["alerts"]
        environment = state["environment"]
        
        # Apply correlation
        correlated_ids, single_ids, stats = await get_correlation_service().correlate_events(alerts, environment)
        
        # Create incident clusters
        incident_clusters = []
        
        # Group alerts by incident_id
        incident_alerts = defaultdict(list)
        for alert in alerts:
            incident_id = alert.get('correlated_incident_id')
            if incident_id:
                incident_alerts[incident_id].append(alert)
        
        # Create incident cluster objects
        for incident_id, incident_alert_list in incident_alerts.items():
            if incident_alert_list:
                representative_alert = incident_alert_list[0]  # First alert as representative
                incident_clusters.append({
                    "incident_id": incident_id,
                    "alerts": incident_alert_list,
                    "cluster_size": len(incident_alert_list),
                    "representative_alert": representative_alert,
                    "created_timestamp": datetime.utcnow().isoformat() + 'Z'
                })
        
        state["incident_clusters"] = incident_clusters
        state["total_incidents"] = len(incident_clusters)
        state["messages"].append({"role": "system", "content": f"Created {len(incident_clusters)} incidents from {len(alerts)} alerts"})
        return state
    except Exception as e:
        state["error"] = str(e)
        return state

# Correlation node function for LangGraph
def correlation_node(state: WorkflowState) -> WorkflowState:
    """Main correlation logic - checks Valkey for existing incidents and correlates alerts"""
    try:
        alerts = state["alerts"]
        environment = state["environment"]
        source = state["source"]
        
        logger.info(f"Starting event correlation on {len(alerts)} alerts from {source} in {environment}")
        
        # Initialize correlation agent
        agent = EventCorrelationAgent()
        
        # Check Valkey for existing incidents and correlate
        incident_clusters = []
        processed_alerts = []
        
        for alert in alerts:
            # Check if this alert can be correlated with existing incidents in Valkey
            existing_incident_id = agent.check_for_existing_incident(alert)
            
            if existing_incident_id:
                # Add alert to existing incident
                logger.info(f"Correlating alert with existing incident: {existing_incident_id}")
                agent.add_alert_to_incident(alert, existing_incident_id)
                
                # Find or create cluster for this incident
                cluster_found = False
                for cluster in incident_clusters:
                    if cluster["incident_id"] == existing_incident_id:
                        cluster["alerts"].append(alert)
                        cluster["cluster_size"] = len(cluster["alerts"])
                        cluster_found = True
                        break
                
                if not cluster_found:
                    # Load existing incident from Valkey
                    existing_alerts = agent.get_incident_alerts(existing_incident_id)
                    incident_clusters.append({
                        "incident_id": existing_incident_id,
                        "alerts": existing_alerts + [alert],
                        "cluster_size": len(existing_alerts) + 1,
                        "representative_alert": existing_alerts[0] if existing_alerts else alert,
                        "created_timestamp": datetime.utcnow().isoformat() + 'Z'
                    })
            else:
                # Create new incident for this alert
                incident_id = str(uuid.uuid4())
                logger.info(f"Creating new incident: {incident_id}")
                
                # Store new incident in Valkey
                agent.create_incident_in_valkey(incident_id, alert)
                
                # Add to clusters
                incident_clusters.append({
                    "incident_id": incident_id,
                    "alerts": [alert],
                    "cluster_size": 1,
                    "representative_alert": alert,
                    "created_timestamp": datetime.utcnow().isoformat() + 'Z'
                })
            
            processed_alerts.append(alert)
        
        # Send incidents to SQS
        for cluster in incident_clusters:
            agent.save_incident(cluster["alerts"], cluster["incident_id"])
        
        state["incident_clusters"] = incident_clusters
        state["total_incidents"] = len(incident_clusters)
        state["messages"].append({
            "role": "system", 
            "content": f"Created {len(incident_clusters)} incidents from {len(alerts)} alerts using Valkey correlation"
        })
        
        logger.info(f"Correlation complete: {len(incident_clusters)} incidents created")
        return state
        
    except Exception as e:
        logger.error(f"Error in correlation_node: {e}")
        state["error"] = str(e)
        return state

# Create LangGraph workflow
def create_correlation_workflow():
    workflow = StateGraph(WorkflowState)
    
    # Add nodes
    workflow.add_node("correlation", correlation_node)
    
    # Add edges
    workflow.add_edge("__start__", "correlation")
    workflow.add_edge("correlation", "__end__")
    
    return workflow.compile()

# FastAPI lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Clustering Correlation API")
    yield
    # Shutdown
    logger.info("Clustering Correlation API shutdown complete")

# FastAPI app
app = FastAPI(
    title="Clustering Correlation API",
    description="FastAPI service for alert correlation and incident creation using LangGraph workflows",
    version="1.0.0",
    lifespan=lifespan
)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "clustering-correlation",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

@app.post("/correlate-alerts", response_model=CorrelationResponse)
async def correlate_alerts(request: CorrelationRequest, background_tasks: BackgroundTasks):
    """Correlate alerts and create incidents"""
    try:
        start_time = datetime.utcnow()
        
        # Create workflow
        workflow = create_correlation_workflow()
        
        # Initial state
        initial_state = WorkflowState(
            alerts=request.alerts,
            environment=request.environment,
            source=request.source,
            incident_clusters=[],
            total_incidents=0,
            messages=[],
            error=None
        )
        
        # Run workflow
        result = await workflow.ainvoke(initial_state)
        
        if result.get("error"):
            raise HTTPException(status_code=500, detail=result["error"])
        
        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        # Convert to response format
        incident_clusters = []
        for cluster in result["incident_clusters"]:
            incident_clusters.append(IncidentCluster(
                incident_id=cluster["incident_id"],
                alerts=cluster["alerts"],
                cluster_size=cluster["cluster_size"],
                representative_alert=cluster["representative_alert"],
                created_timestamp=cluster["created_timestamp"]
            ))
        
        return CorrelationResponse(
            incident_clusters=incident_clusters,
            total_incidents=result["total_incidents"],
            total_alerts_processed=len(request.alerts),
            processing_time_ms=processing_time,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )
        
    except Exception as e:
        logger.error(f"Error in correlation: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004) 