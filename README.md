# Canvas & Clay - Capstone Project 
> Local first digital gallery and artwork management per SRS
> Project allows administrators to securely manage artworks while visitors can browse public digital galleries over the local network 

## Architecture Overview 
- **Frontend** SvelteKit
- **Backend**  Flask (REST API)
- **Database** PostgreSQL (Dockerized)
- **Infra**    Docker Compose for local development and GitHub Actions for CI/CD

Simple Architecture diagram should be added to '/docs/arch.png'

## Running Locally

### Quick Start with Docker 
1. **Install Docker Desktop** from [docker.com](https://www.docker.com/products/docker-desktop/)
2. **Clone the repository**
   ```bash
   git clone https://github.com/cjaron03/canvas-and-clay.git
   cd canvas-and-clay
   ```
3. **Copy environment file** (adjust values if needed)
   ```bash
   cp backend/.env.example backend/.env
   ```
4. **Run**
   ```bash
   cd infra
   docker compose up --build
   ```

**Ports**
- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:5001
- **Database**: localhost:5432

**Stop the application:**
```bash
docker compose down
```

---

## Development Setup (Without Docker)

### Prerequisites
- Node.js 20+
- Python 3.12+
- PostgreSQL 15+

### Backend (Flask)
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

### Frontend (SvelteKit)
```bash
cd frontend
npm install
npm run dev
```

## Docker Optimization

This project uses **alpine linux** base images for optimized performance:
- **75% smaller** container sizes
- **Faster** build and startup times
- **Lower memory** footprint (~200MB vs ~800MB)

## CI/CD Pipeline

This project includes a comprehensive CI/CD pipeline with:

- **Backend Testing**: Python tests with pytest and coverage
- **Frontend Testing**: SvelteKit tests with Vitest
- **Code Quality**: ESLint for frontend, flake8 for backend
- **Docker Builds**: Automated container builds with Alpine Linux
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
