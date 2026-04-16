# Bhu Nirakshak Backend (Node/Express)

## Quick Start
1. `cd server`
2. `npm install`
3. `cp .env.example .env` and update values if needed
4. `npm run dev`

The API will be available at `http://localhost:8080/api`.

## Auth Endpoints
- `POST /api/auth/signup`  
  Body: `{ "name": "", "email": "", "password": "", "role": "Admin|Hawker|Citizen|Enforcement|UrbanDevelopment|Revenue" }`

- `POST /api/auth/login`  
  Body: `{ "email": "", "password": "" }`

- `GET /api/auth/me`  
  Header: `Authorization: Bearer <token>`

## Notes
- Uses SQLite for persistence (`data.db` in this folder).
- JWT auth with a 7-day expiry.
