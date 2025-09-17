# 🔗 Event Correlation Service

[![FastAPI](https://img.shields.io/badge/FastAPI-0.95.1-009688.svg?style=flat&logo=FastAPI)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.0.40-purple.svg?style=flat)](https://github.com/langchain-ai/langgraph)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.3.2-orange.svg?style=flat&logo=scikit-learn)](https://scikit-learn.org)
[![Redis](https://img.shields.io/badge/Redis-Valkey-red.svg?style=flat&logo=redis)](https://redis.io)
[![Python](https://img.shields.io/badge/Python-3.11-blue.svg?style=flat&logo=python)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg?style=flat&logo=docker)](https://docker.com)
[![AWS ECS](https://img.shields.io/badge/AWS-ECS%20Ready-orange.svg?style=flat&logo=amazon-aws)](https://aws.amazon.com/ecs/)

Advanced ML-powered event correlation service that intelligently groups related alerts into incidents using clustering algorithms, semantic similarity, and time-based correlation.

## 🎯 Purpose

- **Correlates related alerts** into meaningful incidents using ML algorithms
- **Reduces alert fatigue** by grouping similar events
- **Semantic similarity analysis** using sentence transformers
- **Time-based clustering** with configurable windows
- **Incident management** with Valkey for persistence and deduplication
- **SQS integration** for downstream incident processing

## 🧠 ML & Correlation Algorithms

### 1. DBSCAN Clustering
Density-based clustering for temporal correlation with configurable parameters.

### 2. Semantic Similarity
Using sentence transformers for message content correlation.

### 3. TF-IDF Vectorization
Text feature extraction for clustering analysis.

### 4. Time Window Correlation
Time-based alert grouping with multiple window sizes.

## 🚀 Quick Start

### Local Development
```bash
pip install -r requirements.txt
uvicorn clustering_correlation_agent:app --host 0.0.0.0 --port 8004 --reload
```

### Docker
```bash
docker build -t correlation:latest .
docker run -p 8004:8004 \
  -e ENVIRONMENT=development \
  -e REDIS_HOST=valkey.example.com \
  -e SQS_QUEUE_URL=https://sqs.region.amazonaws.com/account/queue \
  correlation:latest
```

## 📋 API Endpoints

- `GET /health` - Health check endpoint
- `POST /correlate-alerts` - Correlate alerts into incidents using ML

## ⚙️ Environment Variables

- `ENVIRONMENT` - development/production
- `REDIS_HOST`, `REDIS_PORT` - Valkey/Redis connection
- `REDIS_USERNAME`, `REDIS_PASSWORD` - Valkey authentication
- `SQS_QUEUE_URL` - AWS SQS queue for incident publishing
- `OPENSEARCH_HOST`, `OPENSEARCH_PORT` - OpenSearch for timeline storage

## 🔗 Dependencies

- FastAPI 0.95.1 - Web framework
- LangGraph 0.0.40 - Workflow orchestration
- Scikit-learn 1.3.2 - ML algorithms (DBSCAN, TF-IDF)
- Redis 4.5.4 - Valkey/Redis client
- Sentence-transformers 2.2.2 - Semantic similarity (optional)
- OpenSearch-py 2.3.1 - Timeline storage (optional)

## 📞 Support

Create an issue in this repository or contact the BugRaid AI team.