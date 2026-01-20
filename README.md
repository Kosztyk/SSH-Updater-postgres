
<img width="134" height="134" alt="sshupdater" src="https://github.com/user-attachments/assets/a367e0b3-396f-4e5e-8aa8-fd30bb9aceba" />

 # SSH-Updater-postgres
This is the postgresSQL version.

A tiny web UI to update many Linux hosts over SSH, run ad-hoc scripts, and watch live logs stream back—backed by MongoDB and secured with JWT. 

Great for homelabs, small fleets, or anytime you don’t want to copy-paste the same command into 10 terminals.

# Highlights
• Add & manage hosts (name, IP, SSH user, password, port, root flag)

• One-click apt update/upgrade per host or Update all

• Run custom commands or full bash scripts on selected hosts

• Live log streaming (SSE) for single/all/custom jobs

• JWT authentication with MongoDB storage

• Docker-ready (sample docker-compose included)

# Screenshots
<img width="693" height="446" alt="Screenshot 2025-10-14 at 21 52 34" src="https://github.com/user-attachments/assets/1d47b60c-95b2-4854-a8a0-2ec3ca22c53c" />
<img width="1702" height="453" alt="Screenshot 2025-10-14 at 21 38 48" src="https://github.com/user-attachments/assets/560c2e9f-cdfd-4f88-ab80-c214f6a1487a" />
<img width="1182" height="453" alt="Screenshot 2025-10-14 at 21 40 44" src="https://github.com/user-attachments/assets/8235700e-e9e6-4ba2-a2a9-e0010e7941e9" />
<img width="1182" height="317" alt="Screenshot 2025-10-14 at 21 41 35" src="https://github.com/user-attachments/assets/8ed14d5d-6aac-40d4-8349-9bc74e93b600" />
<img width="1182" height="794" alt="Screenshot 2025-10-14 at 21 42 24" src="https://github.com/user-attachments/assets/996240d1-3d34-499e-b94d-01ecc6e970cc" />

# Quick Start (Docker Compose)

Use the provided docker-compose file to launch SSH Updater along with MongoDB and
mongo-express.

Once started, access the web UI at http://localhost:8099.

The first user can self-register. After that, only logged-in users can add more users.

# docker-compose.yml example

```
services:
  ssh-updater:
    image: kosztyk/ssh-updater-pg:latest
    container_name: ssh-updater-pg
    restart: unless-stopped
    environment:
      DATABASE_URL: postgres://user:password1@db:5432/sshupdaterdb
      NODE_ENV: production
      PORT: "8080"
      PASSWORD_RESET_CODE: "changeme"
    ports:
      - "8080:8080"
    volumes:
      - /app/node_modules
    depends_on:
      - db   

  db:
    image: postgres:15
    container_name: ssh-updater-db
    restart: always
    build: /root/ssh-updater/db-folder
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
      POSTGRES_DB: sshupdaterdb
    volumes:
      - db-data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  pgadmin:
    image: dpage/pgadmin4:9.9
    container_name: pgadmin
    restart: always
    environment:
      PGADMIN_DEFAULT_EMAIL: mail
      PGADMIN_DEFAULT_PASSWORD: password
    ports:
      - "5050:80" # Exposes pgAdmin on port 5050
    volumes:
      - /root/ssh-updaterservers.json:/pgadmin4/servers.json:ro
    depends_on:
      - db        

volumes:
  dbdata:
```

# Security Notes

• Passwords are stored in MongoDB for demo convenience — use SSH keys in production.

• Set a strong JWT_SECRET.

• Prefer HTTPS and restrict network access to known hosts.


# License
MIT License — use freely, no warranty.

Do what you want, just don’t blame us if your cat upgrades the wrong server.
