import json
import boto3
import asyncio
import os
import time
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics.pairwise import cosine_similarity
from sentence_transformers import SentenceTransformer
from collections import defaultdict
import logging
import uuid
import re
import redis
import redis.asyncio
import ssl
import certifi
from contextlib import asynccontextmanager

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
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace('+00:00', 'Z'))

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
        
        # Lambda client removed - log fetcher not needed
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
        
        # Additional SQS queues for incident job processing
        self.edal_jobs_queue_url = "https://sqs.ap-southeast-1.amazonaws.com/528104389666/edal-dev-jobs-queue.fifo"
        self.context_fetcher_queue_url = "https://sqs.ap-southeast-1.amazonaws.com/528104389666/context-fetcher-queue.fifo"
        
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
            try:
                self.sentence_model = SentenceTransformer('all-MiniLM-L6-v2')
            except Exception as e:
                logger.warning(f"Could not load SentenceTransformer: {e}")
            self.sentence_model = None
        # Track SQS acknowledgements by queue type
        self._sqs_acks: Dict[str, List[str]] = {"incidents": [], "timelines": [], "counters": []}

        # Initialize Redis/Valkey client for incident correlation (deferred to startup)
        self.redis = None
        self.redis_pool = None
        self.redis_host = os.environ.get('REDIS_HOST', 'localhost')
        self.redis_port = int(os.environ.get('REDIS_PORT', 6379))
        self.redis_username = os.environ.get('REDIS_USERNAME')
        self.redis_password = os.environ.get('REDIS_PASSWORD')
        
        if self.redis_host == 'localhost':
            logger.warning("REDIS_HOST not configured, Redis/Valkey will be disabled")
            
        try:
            # For serverless Valkey, use proper TLS configuration
            if self.redis_host != 'localhost':
                # Serverless Valkey configuration with proper TLS
                connection_params = {
                    'host': self.redis_host,
                    'port': self.redis_port,
                    'username': self.redis_username,
                    'password': self.redis_password,
                    'ssl': True,
                    'ssl_cert_reqs': ssl.CERT_REQUIRED,
                    'ssl_ca_certs': certifi.where(),
                    'decode_responses': True,
                    'socket_connect_timeout': 2.0,
                    'socket_timeout': 2.5,
                    'health_check_interval': 30,
                    'socket_keepalive': True,
                    'retry_on_timeout': True,
                    'max_connections': 10
                }
            else:
                # Local Redis configuration (no TLS)
                connection_params = {
                    'host': self.redis_host,
                    'port': self.redis_port,
                    'decode_responses': True,
                    'socket_connect_timeout': 2.0,
                    'socket_timeout': 2.5,
                    'max_connections': 10
                }
            
            # Try direct Redis client creation with simpler parameters
            try:
                # First try with minimal SSL configuration
                simple_params = {
                    'host': self.redis_host,
                    'port': self.redis_port,
                    'username': self.redis_username,
                    'password': self.redis_password,
                    'ssl': True,
                    'decode_responses': True,
                    'socket_connect_timeout': 5.0,
                    'socket_timeout': 5.0
                }
                self.redis = redis.asyncio.Redis(**simple_params)
                self.redis_pool = None
            except Exception as simple_error:
                logger.warning(f"Simple SSL config failed: {simple_error}, trying sync client")
                # Fallback to sync Redis client if async doesn't work
                self.redis = redis.Redis(**simple_params)
                self.redis_pool = None
            
            # Connection created, will test on first use
            logger.info(f"Redis/Valkey client configured for {self.redis_host}:{self.redis_port} (connection will be tested on first use)")
                        
        except Exception as e:
            logger.warning(f"Failed to initialize Redis/Valkey connection: {e}")
            logger.warning("Continuing without Valkey correlation - incidents will be created individually")
            self.redis = None
        # Local cache for incidents (OpenSearch removed)
        self.local_incident_cache_path = os.environ.get('INCIDENT_CACHE_FILE', os.path.join('data', 'incidents_cache.json'))
        try:
            os.makedirs(os.path.dirname(self.local_incident_cache_path), exist_ok=True)
        except Exception:
            pass

    async def _ping_redis(self):
        """Helper method to ping Redis with sync/async compatibility"""
        try:
            if hasattr(self.redis, 'ping'):
                # Check if it's an async Redis client
                if hasattr(self.redis, '_async') or 'asyncio' in str(type(self.redis)):
                    return await self.redis.ping()
                else:
                    # It's a sync client, call ping directly
                    return self.redis.ping()
            return False
        except Exception as e:
            logger.debug(f"Redis ping failed: {e}")
            return False

    async def initialize_redis_connection(self):
        """Initialize Redis/Valkey connection with TLS support (called during app startup)"""
        if self.redis_host == 'localhost':
            logger.warning("Skipping Redis initialization - REDIS_HOST not configured")
            return
            
        try:
            logger.info(f"Testing connection to Valkey at {self.redis_host}:{self.redis_port}")
            
            # Test connection with retries
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    ping_result = await self._ping_redis()
                    if ping_result:
                        logger.info(f"Successfully connected to Redis/Valkey at {self.redis_host}:{self.redis_port}")
                        return
                    else:
                        raise Exception("Ping returned False or None")
                except Exception as retry_e:
                    if attempt == max_retries - 1:
                        logger.warning(f"Failed to connect to Redis/Valkey at {self.redis_host} after {max_retries} attempts: {retry_e}")
                        logger.warning("Continuing without Valkey correlation - incidents will be created individually")
                        self.redis = None
                        self.redis_pool = None
                        return
                    else:
                        logger.warning(f"Redis connection attempt {attempt + 1} failed: {retry_e}, retrying...")
                        await asyncio.sleep(1)
                        
        except Exception as e:
            logger.warning(f"Failed to test Redis/Valkey connection: {e}")
            logger.warning("Continuing without Valkey correlation - incidents will be created individually")
            self.redis = None

    async def _ensure_redis_connection(self) -> bool:
        """Ensure Redis connection is available, attempt reconnection if needed"""
        if not self.redis:
            return False
            
        try:
            ping_result = await self._ping_redis()
            return bool(ping_result)
        except Exception as e:
            logger.warning(f"Redis connection lost: {e}, attempting reconnection...")
            # Try to reconnect once
            try:
                if hasattr(self, 'redis_pool') and self.redis_pool:
                    self.redis = redis.Redis(connection_pool=self.redis_pool)
                    ping_result = await self._ping_redis()
                    if ping_result:
                        logger.info("Redis reconnection successful")
                        return True
            except Exception as reconnect_e:
                logger.warning(f"Redis reconnection failed: {reconnect_e}")
            self.redis = None
            return False

    def _get_utc_timestamp(self) -> str:
        """Get current UTC timestamp in proper ISO format with Z suffix"""
        return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace('+00:00', 'Z')
    
    def _safe_timestamp_to_iso(self, timestamp) -> str:
        """Safely convert timestamp to ISO string format"""
        if isinstance(timestamp, datetime):
            return timestamp.isoformat() + 'Z'
        elif isinstance(timestamp, str):
            # If already a string, ensure it ends with Z
            if not timestamp.endswith('Z'):
                return timestamp + 'Z' if not timestamp.endswith('+00:00') else timestamp.replace('+00:00', 'Z')
            return timestamp
        else:
            # Fallback to current time
            return self._get_utc_timestamp()

    async def send_incident_to_edal_jobs_queue(self, incident_data: Dict, environment: str) -> Optional[str]:
        """Send incident information to both edal-dev-jobs-queue and context-fetcher-queue for processing"""
        try:
            # Extract required information from incident data
            company_slug = self.find_company_prefix(incident_data.get('bucket_name', ''), incident_data)
            
            # Create the new EDAL-JOB schema payload for edal jobs queue
            edal_job_payload = {
                "type": "EDAL-JOB",
                "data": {
                    "Session_id": str(uuid.uuid4()),  # Generate a session ID
                    "incident_id": incident_data.get('incident_id', ''),
                    "title": incident_data.get('title', ''),
                    "service": incident_data.get('service', {}),
                    "service_id": incident_data.get('service_id', ''),
                    "source": incident_data.get('source', ''),
                    "description": incident_data.get('description', ''),
                    "priority": incident_data.get('priority', ''),
                    "urgency": incident_data.get('urgency', ''),
                    "priority_score": int(incident_data.get('priority_score', 0)),
                    "compslug": company_slug,
                    "company_id": incident_data.get('company_id', ''),
                    "status": "triggered",
                    "created_at": incident_data.get('created_at', ''),
                    "updated_at": incident_data.get('updated_at', ''),
                    "first_alert_at": incident_data.get('first_alert_at', ''),
                    "last_alert_at": incident_data.get('last_alert_at', ''),
                    "environment": environment,
                }
            }
            
            # Keep the old schema for context fetcher queue
            context_payload = {
                "Session_id": str(uuid.uuid4()),  # Generate a session ID
                "incident_id": incident_data.get('incident_id', ''),
                "title": incident_data.get('title', ''),
                "service": incident_data.get('service', {}),
                "service_id": incident_data.get('service_id', ''),
                "source": incident_data.get('source', ''),
                "description": incident_data.get('description', ''),
                "priority": incident_data.get('priority', ''),
                "urgency": incident_data.get('urgency', ''),
                "priority_score": incident_data.get('priority_score', 0),
                "compslug": company_slug,
                "company_id": incident_data.get('company_id', ''),
                "status": "triggered",
                "created_at": incident_data.get('created_at', ''),
                "updated_at": incident_data.get('updated_at', ''),
                "first_alert_at": incident_data.get('first_alert_at', ''),
                "last_alert_at": incident_data.get('last_alert_at', ''),
                "environment": environment,
            }
            
            # Common message attributes
            message_attributes = {
                'incident_id': {
                    'StringValue': incident_data.get('incident_id', ''),
                    'DataType': 'String'
                },
                'environment': {
                    'StringValue': environment,
                    'DataType': 'String'
                },
                'message_type': {
                    'StringValue': 'incident_job',
                    'DataType': 'String'
                }
            }
            
            # Send to edal jobs queue (FIFO) with new EDAL-JOB schema
            try:
                edal_response = self.sqs.send_message(
                    QueueUrl=self.edal_jobs_queue_url,
                    MessageBody=json.dumps(edal_job_payload),
                    MessageAttributes=message_attributes,
                    MessageGroupId=f"{company_slug}-{environment}",  # Required for FIFO
                    MessageDeduplicationId=f"{incident_data.get('incident_id', '')}-{int(time.time())}"  # Required for FIFO
                )
                edal_message_id = edal_response.get('MessageId')
                logger.info(f"Successfully sent EDAL-JOB incident {incident_data.get('incident_id', '')} to edal jobs queue: {edal_message_id}")
            except Exception as e:
                logger.error(f"Failed to send incident to edal jobs queue: {e}")
                edal_message_id = None
            
            # Send to context fetcher queue (FIFO) with old schema
            try:
                context_response = self.sqs.send_message(
                    QueueUrl=self.context_fetcher_queue_url,
                    MessageBody=json.dumps(context_payload),
                    MessageAttributes=message_attributes,
                    MessageGroupId=f"{company_slug}-{environment}",  # Required for FIFO
                    MessageDeduplicationId=f"{incident_data.get('incident_id', '')}-context-{int(time.time())}"  # Required for FIFO
                )
                context_message_id = context_response.get('MessageId')
                logger.info(f"Successfully sent incident {incident_data.get('incident_id', '')} to context fetcher queue: {context_message_id}")
            except Exception as e:
                logger.error(f"Failed to send incident to context fetcher queue: {e}")
                context_message_id = None
            
            # Return the edal message ID for compatibility
            return edal_message_id
            
        except Exception as e:
            logger.error(f"Failed to send incident to edal jobs queue: {e}")
            return None

    async def check_for_existing_incident_valkey(self, alert: Dict) -> Optional[str]:
        """Check Valkey for existing incidents that could correlate with this alert (replaces OpenSearch logic)"""
        if not await self._ensure_redis_connection():
            return None
            
        try:
            # Create correlation key based on alert characteristics (same logic as OpenSearch)
            # Handle service field which can be a dict or string
            service_field = alert.get('service', '')
            if isinstance(service_field, dict):
                service = service_field.get('name', '').lower()
            else:
                service = str(service_field).lower()
                
            severity = str(alert.get('severity', '')).lower()
            alert_type = str(alert.get('type', '')).lower()
            source = str(alert.get('source', '')).lower()
            company_id = alert.get('company_id', '')
            
            # Use sets to track incidents by characteristics (Serverless Valkey doesn't support KEYS)
            # Look for recent incidents by checking specific correlation sets
            cutoff_time = datetime.utcnow() - timedelta(minutes=60)
            
            # Check for incidents with same service
            service_set_key = f"incidents:service:{service}:company:{company_id}"
            incident_ids = await self.redis.smembers(service_set_key)
            
            for incident_id in incident_ids:
                if incident_id:
                    # Get incident metadata using the incident_id
                    incident_meta_key = f"incident:{incident_id}:meta"
                    incident_data = await self.redis.hgetall(incident_meta_key)
                    
                    if incident_data:
                        # Check if incident is recent
                        created_at = incident_data.get('created_at', '')
                        
                        if created_at:
                            try:
                                created_time = datetime.fromisoformat(created_at.rstrip('Z'))
                                
                                if created_time > cutoff_time:
                                    # Check for correlation based on similarity (same logic as OpenSearch)
                                    representative_alert_json = incident_data.get('representative_alert', '{}')
                                    representative_alert = json.loads(representative_alert_json)
                                    
                                    if self._are_alerts_similar_for_correlation(alert, representative_alert):
                                        return incident_id
                            except Exception:
                                continue
            
            return None
                                 
        except Exception as e:
            logger.warning(f"Error checking for existing incidents in Valkey: {e}")
            return None

    def _are_alerts_similar_for_correlation(self, alert1: Dict, alert2: Dict) -> bool:
        """Check if two alerts are similar enough to correlate (enhanced with title/message similarity)"""
        similarity_score = 0
        total_checks = 0
        
        # Check company similarity first (critical for multi-tenant) - if different companies, no correlation
        company1 = str(alert1.get('company_id', ''))
        company2 = str(alert2.get('company_id', ''))
        if company1 != company2:
            return False  # Never correlate across different companies
        
        # Check service similarity
        service1 = str(alert1.get('service', '')).lower()
        service2 = str(alert2.get('service', '')).lower()
        if service1 == service2:
            similarity_score += 2  # Service match is important
        total_checks += 2
        
        # Check title/message similarity (MOST IMPORTANT)
        title1 = str(alert1.get('title', '')).lower().strip()
        title2 = str(alert2.get('title', '')).lower().strip()
        
        # Exact title match
        if title1 and title2 and title1 == title2:
            similarity_score += 4  # Exact title match is very important
        # Similar title (contains key words)
        elif title1 and title2:
            # Check if titles share significant words (excluding common words)
            common_words = {'the', 'a', 'an', 'on', 'in', 'at', 'of', 'for', 'to', 'is', 'was', 'and', 'or'}
            words1 = set(title1.split()) - common_words
            words2 = set(title2.split()) - common_words
            
            if words1 and words2:
                common_significant_words = words1.intersection(words2)
                if len(common_significant_words) >= 2:  # At least 2 significant words in common
                    similarity_score += 2
                elif len(common_significant_words) >= 1:  # At least 1 significant word in common
                    similarity_score += 1
        total_checks += 4
        
        # Check severity similarity  
        severity1 = str(alert1.get('severity', '')).lower()
        severity2 = str(alert2.get('severity', '')).lower()
        if severity1 == severity2:
            similarity_score += 1
        total_checks += 1
        
        # Check source similarity
        source1 = str(alert1.get('source', '')).lower()
        source2 = str(alert2.get('source', '')).lower()
        if source1 == source2:
            similarity_score += 1
        total_checks += 1
        
        # Check alert type similarity
        type1 = str(alert1.get('type', '')).lower()
        type2 = str(alert2.get('type', '')).lower()
        if type1 == type2:
            similarity_score += 1
        total_checks += 1
        
        # Calculate similarity ratio
        similarity_ratio = similarity_score / total_checks if total_checks > 0 else 0
        
        # Higher threshold (70%) to reduce over-correlation - requires stronger similarity
        threshold = 0.7
        is_similar = similarity_ratio >= threshold
        
        # Debug logging
        logger.debug(f"Alert similarity check:")
        logger.debug(f"  Alert1 title: '{title1}' | Alert2 title: '{title2}'")
        logger.debug(f"  Alert1 service: '{service1}' | Alert2 service: '{service2}'")
        logger.debug(f"  Score: {similarity_score}/{total_checks} = {similarity_ratio:.2f} ({'MATCH' if is_similar else 'NO MATCH'}, threshold={threshold})")
        
        return is_similar

    async def create_incident_in_valkey(self, incident_id: str, alert: Dict):
        """Create a new incident in Valkey for future correlation"""
        if not await self._ensure_redis_connection():
            return
            
        try:
            current_time = self._get_utc_timestamp()
            
            # Store incident metadata
            incident_key = f"incident:{incident_id}:meta"
            await self.redis.hset(incident_key, "incident_id", incident_id)
            await self.redis.hset(incident_key, "created_at", current_time)
            await self.redis.hset(incident_key, "last_updated", current_time)
            await self.redis.hset(incident_key, "alert_count", 1)
            await self.redis.hset(incident_key, "status", "open")
            await self.redis.hset(incident_key, "representative_alert", json.dumps(alert))
            
            # Create searchable keys for correlation
            # Handle service field which can be a dict or string
            service_field = alert.get('service', '')
            if isinstance(service_field, dict):
                service = service_field.get('name', '').lower()
            else:
                service = str(service_field).lower()
                
            severity = str(alert.get('severity', '')).lower()
            alert_type = str(alert.get('type', '')).lower()
            source = str(alert.get('source', '')).lower()
            company_id = alert.get('company_id', '')
            
            # Add incident to correlation sets (instead of individual keys)
            correlation_sets = [
                f"incidents:service:{service}:company:{company_id}",
                f"incidents:severity:{severity}:company:{company_id}",
                f"incidents:type:{alert_type}:company:{company_id}",
                f"incidents:source:{source}:company:{company_id}"
            ]
            
            for set_key in correlation_sets:
                await self.redis.sadd(set_key, incident_id)
                await self.redis.expire(set_key, 86400)  # 24 hour expiration
                
            # Set expiration (24 hours)
            await self.redis.expire(incident_key, 86400)
            
            logger.info(f"Created incident {incident_id} in Valkey")
            
        except Exception as e:
            logger.warning(f"Error creating incident in Valkey: {e}")

    def add_alert_to_incident_valkey(self, alert: Dict, incident_id: str):
        """Add an alert to an existing incident in Valkey"""
        if not self._ensure_redis_connection():
            return
            
        try:
            # Update incident metadata
            incident_key = f"incident:{incident_id}:meta"
            self.redis.hset(incident_key, "last_updated", self._get_utc_timestamp())
            self.redis.hincrby(incident_key, "alert_count", 1)
            
            # Set expiration (24 hours)
            self.redis.expire(incident_key, 86400)
            
            logger.info(f"Updated incident {incident_id} metadata in Valkey")
            
        except Exception as e:
            logger.warning(f"Error updating incident metadata in Valkey: {e}")

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
        """Log timeline event (OpenSearch removed - using debug logs only)."""
        # OpenSearch removed - using debug logs only
        logger.debug(f"Timeline event for incident {incident_id}: {event}")
        return incident_id

    def _index_incident_document(self, incident: Dict[str, Any]) -> Optional[str]:
        """Index incident document (OpenSearch removed - using debug logs only)."""
        logger.debug(f"Incident document: {incident.get('id')}")
        return incident.get("id")

    def _fetch_incident_document(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Fetch incident document (OpenSearch removed - using local cache only)."""
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
            "created_at": alert.get("createdAt") or (self._safe_timestamp_to_iso(alert.get("parsed_time")) if alert.get("parsed_time") else None),
            "updated_at": alert.get("updatedAt"),
            "sources": alert.get("sources"),
            "policy_names": alert.get("alertPolicyNames"),
            "condition_names": alert.get("alertConditionNames"),
            "impacted_entities": alert.get("impactedEntities")
        }

    async def _update_incident_with_alerts(self, incident_id: str, new_alerts: List[Dict[str, Any]], environment: str) -> Optional[Dict[str, Any]]:
        """Append alerts to an existing incident, promote to correlated, update counters/timestamps, reindex and notify SQS."""
        # Since we removed OpenSearch, create a minimal incident structure for correlation
        existing = {
            "id": incident_id,
            "data": {
                "alerts": [],
                "total_alerts": 1,
                "status": "triggered"
            },
            "created_at": self._get_utc_timestamp(),
            "updated_at": self._get_utc_timestamp()
        }
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
                # Find the latest timestamp from the times array
                latest_time = max(times)
                last_alert_at = self._safe_timestamp_to_iso(latest_time)

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
        """
        Calculate BigPanda-style multi-signal correlation using all 7 correlation techniques:
        1. Time-based correlation
        2. Rule-based correlation  
        3. Pattern-based correlation
        4. Topology-based correlation
        5. Domain-based correlation
        6. History-based correlation
        7. Codebook correlation
        """
        try:
            signals = {}
            
            # 1. TIME-BASED CORRELATION (BigPanda technique #1)
            time_score = self.calculate_time_proximity_score(alert1, alert2)
            signals['time_based'] = {
                'score': time_score,
                'explanation': f'Time proximity correlation: {time_score:.2f}',
                'technique': 'Time-based event correlation'
            }
            
            # 2. RULE-BASED CORRELATION (BigPanda technique #2)
            rule_score = self.calculate_rule_based_correlation(alert1, alert2)
            signals['rule_based'] = {
                'score': rule_score,
                'explanation': f'Rule-based matching: {rule_score:.2f}',
                'technique': 'Rule-based event correlation'
            }
            
            # 3. PATTERN-BASED CORRELATION (BigPanda technique #3)
            pattern_score = self.calculate_pattern_based_correlation(alert1, alert2)
            signals['pattern_based'] = {
                'score': pattern_score,
                'explanation': f'Pattern similarity: {pattern_score:.2f}',
                'technique': 'Pattern-based event correlation'
            }
            
            # 4. TOPOLOGY-BASED CORRELATION (BigPanda technique #4)
            topology_score = self.calculate_topology_based_correlation(alert1, alert2)
            signals['topology_based'] = {
                'score': topology_score,
                'explanation': f'Topology/service correlation: {topology_score:.2f}',
                'technique': 'Topology-based event correlation'
            }
            
            # 5. DOMAIN-BASED CORRELATION (BigPanda technique #5)
            domain_score = self.calculate_domain_based_correlation(alert1, alert2)
            signals['domain_based'] = {
                'score': domain_score,
                'explanation': f'Domain/source correlation: {domain_score:.2f}',
                'technique': 'Domain-based event correlation'
            }
            
            # 6. HISTORY-BASED CORRELATION (BigPanda technique #6)
            history_score = self.calculate_history_based_correlation(alert1, alert2)
            signals['history_based'] = {
                'score': history_score,
                'explanation': f'Historical pattern match: {history_score:.2f}',
                'technique': 'History-based event correlation'
            }
            
            # 7. CODEBOOK CORRELATION (BigPanda technique #7)
            codebook_score = self.calculate_codebook_correlation(alert1, alert2)
            signals['codebook'] = {
                'score': codebook_score,
                'explanation': f'Codebook matrix match: {codebook_score:.2f}',
                'technique': 'Codebook event correlation'
            }
            
            # BigPanda-style weighted scoring (balanced across all 7 techniques)
            weights = {
                'time_based': 0.20,      # 20% - Time proximity is critical
                'rule_based': 0.15,      # 15% - Explicit rule matching
                'pattern_based': 0.20,   # 20% - AI pattern recognition (most important)
                'topology_based': 0.15,  # 15% - Service/infrastructure topology
                'domain_based': 0.10,    # 10% - Domain/source correlation
                'history_based': 0.10,   # 10% - Historical pattern matching
                'codebook': 0.10         # 10% - Codebook matrix correlation
            }
            
            # Calculate weighted total score (BigPanda approach)
            total_score = sum(signals[signal]['score'] * weights[signal] for signal in weights)
            
            # BigPanda-style confidence calculation
            active_signals = sum(1 for signal in signals.values() if signal['score'] > 0.1)
            confidence = active_signals / len(signals)
            
            # Add compression ratio calculation (BigPanda KPI)
            compression_ratio = self.calculate_compression_ratio(total_score)
            signals['compression_info'] = {
                'ratio': compression_ratio,
                'explanation': f'Expected compression: {compression_ratio:.1%}'
            }
            
            return total_score, confidence, signals
            
        except Exception as e:
            logger.warning(f"Error calculating BigPanda-style multi-signal correlation: {e}")
            return 0.0, 0.0, {}

    def calculate_rule_based_correlation(self, alert1: Dict, alert2: Dict) -> float:
        """
        BigPanda Rule-based correlation: Compare events to predefined rules
        Rules check specific values like service type, severity, company, etc.
        """
        try:
            rule_matches = 0
            total_rules = 0
            
            # Rule 1: Same company (critical for multi-tenant)
            total_rules += 1
            if alert1.get('company_id') == alert2.get('company_id') and alert1.get('company_id'):
                rule_matches += 1
            
            # Rule 2: Same service or service family
            total_rules += 1
            service1 = str(alert1.get('service', '')).lower()
            service2 = str(alert2.get('service', '')).lower()
            if service1 == service2 and service1:
                rule_matches += 1
            
            # Rule 3: Similar severity levels
            total_rules += 1
            sev1 = str(alert1.get('severity', '')).lower()
            sev2 = str(alert2.get('severity', '')).lower()
            if sev1 == sev2 and sev1:
                rule_matches += 1
            
            # Rule 4: Same environment
            total_rules += 1
            env1 = str(alert1.get('environment', '')).lower()
            env2 = str(alert2.get('environment', '')).lower()
            if env1 == env2 and env1:
                rule_matches += 1
            
            # Rule 5: Same alert type/category
            total_rules += 1
            type1 = str(alert1.get('alert_type', alert1.get('type', ''))).lower()
            type2 = str(alert2.get('alert_type', alert2.get('type', ''))).lower()
            if type1 == type2 and type1:
                rule_matches += 1
            
            return rule_matches / total_rules if total_rules > 0 else 0.0
            
        except Exception as e:
            logger.warning(f"Error in rule-based correlation: {e}")
            return 0.0

    def calculate_pattern_based_correlation(self, alert1: Dict, alert2: Dict) -> float:
        """
        BigPanda Pattern-based correlation: Uses ML to find events matching defined patterns
        Combines semantic similarity with pattern recognition
        """
        try:
            # Use semantic similarity as base pattern matching
            semantic_score = self.calculate_semantic_similarity(alert1, alert2)
            
            # Pattern enhancement: Check for common error patterns
            title1 = str(alert1.get('title', '')).lower()
            title2 = str(alert2.get('title', '')).lower()
            
            # Common patterns in alert titles
            error_patterns = [
                'timeout', 'connection', 'failed', 'error', 'exception',
                'unavailable', 'down', 'high', 'low', 'critical'
            ]
            
            pattern_matches = 0
            for pattern in error_patterns:
                if pattern in title1 and pattern in title2:
                    pattern_matches += 1
            
            # Combine semantic similarity with pattern matching
            pattern_bonus = min(pattern_matches * 0.1, 0.3)  # Max 30% bonus
            
            return min(semantic_score + pattern_bonus, 1.0)
            
        except Exception as e:
            logger.warning(f"Error in pattern-based correlation: {e}")
            return 0.0

    def calculate_topology_based_correlation(self, alert1: Dict, alert2: Dict) -> float:
        """
        BigPanda Topology-based correlation: Uses network/service topology
        Maps alerts to affected nodes and their relationships
        """
        try:
            # Service topology correlation
            service1 = str(alert1.get('service', '')).lower()
            service2 = str(alert2.get('service', '')).lower()
            
            # Direct service match
            if service1 == service2 and service1:
                return 1.0
            
            # Service dependency patterns (simplified topology)
            service_dependencies = {
                'database': ['api', 'backend', 'service'],
                'api': ['frontend', 'web', 'client'],
                'cache': ['api', 'database', 'backend'],
                'queue': ['worker', 'processor', 'consumer']
            }
            
            # Check if services are in same dependency chain
            for primary, dependents in service_dependencies.items():
                if primary in service1:
                    for dependent in dependents:
                        if dependent in service2:
                            return 0.7  # High correlation for dependent services
                if primary in service2:
                    for dependent in dependents:
                        if dependent in service1:
                            return 0.7
            
            # Host/node correlation
            host1 = alert1.get('host', alert1.get('node', ''))
            host2 = alert2.get('host', alert2.get('node', ''))
            if host1 == host2 and host1:
                return 0.8
            
            return 0.0
            
        except Exception as e:
            logger.warning(f"Error in topology-based correlation: {e}")
            return 0.0

    def calculate_domain_based_correlation(self, alert1: Dict, alert2: Dict) -> float:
        """
        BigPanda Domain-based correlation: Connects events from related IT domains
        (network, application, infrastructure)
        """
        try:
            # Source system correlation (monitoring domains)
            source1 = str(alert1.get('source', '')).lower()
            source2 = str(alert2.get('source', '')).lower()
            
            # Direct source match
            if source1 == source2 and source1:
                return 1.0
            
            # Domain groupings
            monitoring_domains = {
                'infrastructure': ['prometheus', 'nagios', 'zabbix', 'datadog'],
                'application': ['newrelic', 'appdynamics', 'dynatrace'],
                'network': ['snmp', 'netflow', 'prtg'],
                'cloud': ['cloudwatch', 'azure', 'gcp'],
                'logging': ['elk', 'splunk', 'fluentd', 'logstash']
            }
            
            # Check if sources are in same domain
            for domain, sources in monitoring_domains.items():
                source1_in_domain = any(s in source1 for s in sources)
                source2_in_domain = any(s in source2 for s in sources)
                if source1_in_domain and source2_in_domain:
                    return 0.6  # Same monitoring domain
            
            return 0.0
            
        except Exception as e:
            logger.warning(f"Error in domain-based correlation: {e}")
            return 0.0

    def calculate_history_based_correlation(self, alert1: Dict, alert2: Dict) -> float:
        """
        BigPanda History-based correlation: Matches new events with historical patterns
        Uses past correlation decisions to improve future matching
        """
        try:
            # Simplified historical pattern matching
            # In production, this would query historical correlation database
            
            # Create signature for alert patterns
            sig1 = self.create_alert_signature(alert1)
            sig2 = self.create_alert_signature(alert2)
            
            # Check if we've seen this pattern combination before
            # This is a simplified version - real implementation would use Redis/DB
            historical_patterns = getattr(self, '_historical_patterns', {})
            
            pattern_key = tuple(sorted([sig1, sig2]))
            if pattern_key in historical_patterns:
                return historical_patterns[pattern_key]
            
            # For new patterns, use heuristic based on signature similarity
            sig_similarity = len(set(sig1.split('|')) & set(sig2.split('|'))) / max(len(sig1.split('|')), len(sig2.split('|')), 1)
            
            return min(sig_similarity, 0.8)  # Cap at 80% for historical matching
            
        except Exception as e:
            logger.warning(f"Error in history-based correlation: {e}")
            return 0.0

    def calculate_codebook_correlation(self, alert1: Dict, alert2: Dict) -> float:
        """
        BigPanda Codebook correlation: Uses coded event matrix mapping
        Events are coded and mapped to correlation matrix
        """
        try:
            # Create codebook entries for alerts
            code1 = self.generate_alert_code(alert1)
            code2 = self.generate_alert_code(alert2)
            
            # Codebook matrix (simplified - real implementation would be larger)
            codebook_matrix = {
                ('DB', 'API'): 0.8,    # Database issues often affect APIs
                ('NET', 'APP'): 0.7,   # Network issues affect applications
                ('CPU', 'MEM'): 0.6,   # CPU and memory often correlated
                ('DISK', 'IO'): 0.9,   # Disk and I/O highly correlated
                ('AUTH', 'SEC'): 0.8,  # Authentication and security related
            }
            
            # Check direct code match
            if code1 == code2:
                return 1.0
            
            # Check codebook matrix
            code_pair = tuple(sorted([code1, code2]))
            if code_pair in codebook_matrix:
                return codebook_matrix[code_pair]
            
            # Check reverse pair
            reverse_pair = (code_pair[1], code_pair[0])
            if reverse_pair in codebook_matrix:
                return codebook_matrix[reverse_pair]
            
            return 0.0
            
        except Exception as e:
            logger.warning(f"Error in codebook correlation: {e}")
            return 0.0

    def create_alert_signature(self, alert: Dict) -> str:
        """Create a signature for historical pattern matching"""
        service = str(alert.get('service', 'unknown'))[:10]
        source = str(alert.get('source', 'unknown'))[:10]
        severity = str(alert.get('severity', 'unknown'))[:5]
        return f"{service}|{source}|{severity}"

    def generate_alert_code(self, alert: Dict) -> str:
        """Generate codebook code for alert"""
        title = str(alert.get('title', '')).lower()
        
        # Codebook mapping based on alert content
        if any(word in title for word in ['database', 'db', 'sql']):
            return 'DB'
        elif any(word in title for word in ['api', 'endpoint', 'service']):
            return 'API'
        elif any(word in title for word in ['network', 'connection', 'timeout']):
            return 'NET'
        elif any(word in title for word in ['cpu', 'processor']):
            return 'CPU'
        elif any(word in title for word in ['memory', 'ram', 'oom']):
            return 'MEM'
        elif any(word in title for word in ['disk', 'storage', 'space']):
            return 'DISK'
        elif any(word in title for word in ['io', 'input', 'output']):
            return 'IO'
        elif any(word in title for word in ['auth', 'login', 'permission']):
            return 'AUTH'
        elif any(word in title for word in ['security', 'ssl', 'certificate']):
            return 'SEC'
        else:
            return 'APP'  # Default application code

    def calculate_compression_ratio(self, correlation_score: float) -> float:
        """Calculate expected compression ratio based on correlation score (BigPanda KPI)"""
        # Higher correlation score = higher compression potential
        # BigPanda targets 70-85% compression
        base_compression = 0.70  # 70% base compression
        score_bonus = correlation_score * 0.25  # Up to 25% additional compression
        return min(base_compression + score_bonus, 0.95)  # Cap at 95%
    
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
        """Match alerts with existing incidents within a time window using Valkey lookback (replaces OpenSearch)."""
        try:
            logger.info(f"\n🔍 Searching for existing incidents to match with:")
            logger.info(f"   Title: {title}")
            logger.info(f"   Service: {service}")
            logger.info(f"   Company: {company_id}")
            
            # Use first alert from group for Valkey matching
            if group_alerts:
                first_alert = group_alerts[0].copy()
                first_alert['company_id'] = company_id
                first_alert['service'] = service
                
                # Check Valkey for existing incidents using our new method
                matching_incident = await self.check_for_existing_incident_valkey(first_alert)
                
                if matching_incident:
                    logger.info(f"✅ Found matching incident in Valkey: {matching_incident}")
                    return matching_incident
                else:
                    logger.info(f"🚫 No matching incident found in Valkey")
            
                return None
            
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
            alert_times = [alert.get('parsed_time') for alert in group_alerts if alert.get('parsed_time')]
            first_alert_time = min(alert_times) if alert_times else datetime.utcnow()
            last_alert_time = max(alert_times) if alert_times else datetime.utcnow()
            
            # Determine primary candidate alert (highest priority, then earliest time)
            def _priority_rank(alert: Dict) -> int:
                pr = (alert.get('priority') or alert.get('severity') or '').lower()
                mapping = {'p0':5,'critical':5,'p1':4,'high':4,'p2':3,'medium':3,'p3':2,'low':2,'p4':1}
                return mapping.get(pr, 3)
            sorted_alerts = sorted(
                group_alerts,
                key=lambda a: (-_priority_rank(a), a.get('parsed_time') or datetime.utcnow())
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
                "created_at": self._safe_timestamp_to_iso(first_alert_time),
                "updated_at": self._safe_timestamp_to_iso(last_alert_time),
                "first_alert_at": self._safe_timestamp_to_iso(first_alert_time),
                "last_alert_at": self._safe_timestamp_to_iso(last_alert_time),
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
            
            # Log fetcher lambda removed - not needed
            
            # Send incident to edal jobs queue
            await self.send_incident_to_edal_jobs_queue(incident, environment)
            
            # Store incident in Valkey for future correlation (use representative alert)
            representative_alert = group_alerts[0]  # Use first alert as representative
            await self.create_incident_in_valkey(incident_id, representative_alert)
            
            # Persist incident locally (OpenSearch removed)
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
            
            # Store timeline entries (OpenSearch removed - using debug logs only)
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
            
            alert_time = alert.get('parsed_time', datetime.utcnow())
            
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
                "created_at": self._safe_timestamp_to_iso(alert_time),
                "updated_at": self._safe_timestamp_to_iso(alert_time),
                "first_alert_at": self._safe_timestamp_to_iso(alert_time),
                "last_alert_at": self._safe_timestamp_to_iso(alert_time),
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
            
            # Log fetcher lambda removed - not needed

            # Send incident to edal jobs queue
            await self.send_incident_to_edal_jobs_queue(incident, environment)

            # Store incident in Valkey for future correlation
            await self.create_incident_in_valkey(incident_id, alert)

            # Persist incident locally (OpenSearch removed)
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
                    # Add alert to incident in Valkey
                    self.add_alert_to_incident_valkey(alert, existing_incident)
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
                            # Add alert to incident in Valkey
                            self.add_alert_to_incident_valkey(alert, existing_incident)
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
                                # Add each alert to incident in Valkey
                                self.add_alert_to_incident_valkey(alert, existing_incident)
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

    # _trigger_log_fetcher method removed - log fetcher lambda not needed

# Correlation node function for LangGraph
async def correlation_node(state: WorkflowState) -> WorkflowState:
    """Main correlation logic - uses Valkey for existing incident matching"""
    try:
        alerts = state["alerts"]
        environment = state["environment"]
        source = state["source"]
        
        logger.info(f"Starting event correlation on {len(alerts)} alerts from {source} in {environment}")
        
        # Initialize correlation agent
        agent = EventCorrelationAgent()
        logger.info(f"Correlation agent initialized with Valkey")
        
        # Preserve original alert sources, but ensure source field exists
        for alert in alerts:
            if not alert.get('source'):
                alert['source'] = source  # Only set source if it's missing
        
        # Use the existing correlate_events method which now uses Valkey
        correlated_ids, single_ids, stats = await agent.correlate_events(alerts, environment)
        
        # Convert to incident clusters for response
        incident_clusters = []
        
        # Add correlated incidents
        for incident_id in correlated_ids:
            incident_clusters.append({
                "incident_id": incident_id,
                "alerts": [],  # Not storing individual alerts in clusters for efficiency
                "cluster_size": 1,  # Will be updated by actual correlation
                "representative_alert": alerts[0] if alerts else {},
                "created_timestamp": agent._get_utc_timestamp()
            })
        
        # Add single incidents
        for incident_id in single_ids:
            incident_clusters.append({
                "incident_id": incident_id,
                "alerts": [],
                "cluster_size": 1,
                "representative_alert": alerts[0] if alerts else {},
                "created_timestamp": agent._get_utc_timestamp()
            })
        
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
    logger.info("Starting Clustering Correlation API with Valkey")
    
    # Initialize Redis connection if available
    if hasattr(app.state, 'correlation_service') and app.state.correlation_service:
        await app.state.correlation_service.initialize_redis_connection()
    
    yield
    
    # Shutdown
    logger.info("Clustering Correlation API shutdown complete")

# Initialize correlation service
correlation_service = EventCorrelationAgent()

# FastAPI app
app = FastAPI(
    title="Clustering Correlation API",
    description="FastAPI service for alert correlation and incident creation using LangGraph workflows with Valkey",
    version="1.0.0",
    lifespan=lifespan
)

# Store correlation service in app state
app.state.correlation_service = correlation_service

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "clustering-correlation",
        "valkey_enabled": True,
        "timestamp": datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace('+00:00', 'Z')
    }

@app.post("/correlate-alerts", response_model=CorrelationResponse)
async def correlate_alerts(request: CorrelationRequest, background_tasks: BackgroundTasks):
    """Correlate alerts and create incidents using Valkey"""
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004) 