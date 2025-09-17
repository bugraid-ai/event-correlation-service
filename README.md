# Event Correlation Service

FastAPI service with LangGraph that correlates alerts into incidents using clustering algorithms, semantic similarity, and Valkey for incident management. Sends incidents to SQS.

## Files Structure
```
event-correlation-service/
├── README.md
├── requirements.txt (from ecs-deployment/requirements/requirements-correlation.txt)
├── Dockerfile (from ecs-deployment/docker/Dockerfile.correlation)
├── clustering_correlation_agent.py (from ecs-deployment/services/clustering_correlation_agent.py)
├── task-definition.json (from ecs-deployment/infrastructure/task-definitions/correlation-task.json)
├── test_valkey_correlation.py (from ecs-deployment/test_valkey_correlation.py)
├── test_valkey_simple.py (from ecs-deployment/test_valkey_simple.py)
└── deploy.sh (deployment script)
```

## Deployment
```bash
./deploy.sh
```

## Environment Variables
- `ENVIRONMENT`: development/production
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_USERNAME`, `REDIS_PASSWORD`: Valkey connection
- `OPENSEARCH_HOST`, `OPENSEARCH_PORT`: OpenSearch for timeline storage
- `SQS_QUEUE_URL`: AWS SQS queue for incidents
- `AWS_DEFAULT_REGION`: AWS region

## Port
- Service runs on port **8004**
- Health check: `GET /health`
- Main endpoint: `POST /correlate-alerts`

## Features
- DBSCAN clustering
- Semantic similarity with sentence-transformers
- Valkey-based incident correlation
- OpenSearch timeline storage
- SQS incident publishing
