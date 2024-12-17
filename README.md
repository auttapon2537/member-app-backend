# Member-App Backend Project

This is the backend service for Member-App. It provides the API and database management functionalities for handling Priviledes & Points. This backend is built using Go (Golang) and relies on MySQL for data persistence.

## Features

- **User Authentication**: JWT-based authentication for secure access to the API.
- **Profile Management**: Ability to create and retrieve user profiles.
- **REST API**: Standard RESTful API

## Technologies

- **Go (Golang)**: Main programming language for building the service.
- **Fiber**: High-performance web framework for Go.
- **JWT**: For authentication and token-based authorization.
- **MySQL**: Database used for data storage.
- **Docker**: Containerization for easier deployment and environment management.

## Environment Setup

### Development Setup

1. Clone the repository:
```bash
git clone https://github.com/auttapon2537/member-app-backend.git
cd member-app-backend
```

2. Run project:
```bash
docker-compose up -d
```

3. Import database:

Go to phpmyadmin http://localhost:8080

use file `member.sql` in folder `docs`

4. Check service is running:
```bash
curl -X GET http://localhost:3001/
```

and you can following APIs Document in docs folder
