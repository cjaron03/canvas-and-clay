# Canvas & Clay - Capstone Project 
> Local first digital gallery and artwork management per SRS
> Project allows administrators to securely manage artworks while visitors can browse public digital galleries over the local network 

## Architecture Overview 
- **Frontend** SvelteKit
- **Backend**  Flask (REST API)
- **Database** PostgreSQL (Dockerized)
- **Infra**    Docker Compose for local development and GitHub Actions for CI/CD

Simple Architecture diagram should be added to '/docs/arch.png'

## Getting Started

### Prerequisites
- Node.js 20+
- Python 3.12+
- Docker & Docker Compose

### Local Development Setup

#### Backend (Flask)
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

#### Frontend (SvelteKit)
```bash
cd frontend
npm install
npm run dev
```

#### Full Stack with Docker
```bash
cd infra
docker-compose up --build
```

## CI/CD Pipeline

This project includes a comprehensive CI/CD pipeline with:

- **Backend Testing**: Python tests with pytest and coverage
- **Frontend Testing**: SvelteKit tests with Vitest
- **Code Quality**: ESLint for frontend, flake8 for backend
- **Docker Builds**: Automated container builds
- **Security Scanning**: Trivy vulnerability scanning
- **Deployment**: Automated staging and production deployments

### Pipeline Triggers
- **Push to `main`**: Full pipeline + production deployment
- **Push to `develop`**: Full pipeline + staging deployment  
- **Pull Requests**: Full pipeline validation

## Project Structure
```
├── backend/           # Flask API
│   ├── app.py         # Main application
│   ├── requirements.txt
│   ├── Dockerfile
│   └── tests/         # Test files
├── frontend/          # SvelteKit app
│   ├── src/           # Source code
│   ├── package.json
│   └── Dockerfile
├── infra/             # Infrastructure
│   ├── docker-compose.yml
│   └── docker-compose.test.yml
└── .github/workflows/ # CI/CD configuration
```