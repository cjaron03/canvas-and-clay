# Canvas & Clay - Capstone Project 
> Local first digital gallery and artwork manangment per SRS
> Project allows administrators to securely manage artworks while vistors can browse public digital galleries over the local network 

## Architecture Overview 
- **Frontend** SvelteKit
- **Backend**  Flask (REST API)
- **Database** PostgreSQL (Dockerized)
- **Infra**    Docker Compose for local development and Github actions for CI/CD

Simple Architecture diagram should be added to '/docs/arch.png'

## Getting Setup
1. **Requirements** Node 20+, Python 3.12+, Docker 
2: **Install (Frontend)**
    '''bash
    cd frontend
    npm install
    npm run dev