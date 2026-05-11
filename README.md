[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/NYCU-SDC/clustron-backend)

# clustron-backend

This is the backend of NYCU SDC Clustron Project.

We aim to create a service to visuallize the LDAP access managing, Slurm operation, and resource usage on remote computer cluster.

# Table of Content

- [Deploy](#deploy)
- [Developer Guide](#get-started)

# Deploy

## Dependent Services

Clustron depend the following services to work properly.

1. Postgres 18: for data storage.
2. OpenLDAP 1.5.0: one of the main purpose of Clustron is to manage system user account with LDAP.

## LDAP Initialization

Clustron require specific class and path to be exist in LDAP.
The initialization `ldif` looks like bellow:

```ldif
# ou=People
dn: ou=People,dc=your_dc
objectClass: organizationalUnit
ou: People

# ou=Groups
dn: ou=Groups,dc=your_dc
objectClass: organizationalUnit
ou: Groups
```

Substitute the `your_dc` part as needed.

## OAuth

Clustron authorize login via 3rd-party OAuth service.

For users to be able to login to the system, enable one of the following:

- Google OAuth
- NYCU OAuth

For users to be able to import public keys from GitHub, enable GitHub OAuth Service.

| OAuth Service | Environment Variables                                  | Redirect URL                                                                      | Relative Functions            |
| ------------- | ------------------------------------------------------ | --------------------------------------------------------------------------------- | ----------------------------- |
| Google OAuth  | `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET` | `/api/login/oauth/google`, `/api/bind/oauth/google`, `/api/oauth/google/callback` | Login                         |
| NYCU OAuth    | `NYCU_OAUTH_CLIENT_ID`, `NYCU_OAUTH_CLIENT_SECRET`     | `/api/login/oauth/nycu`, `/api/bind/oauth/nycu`, `/api/oauth/google/nycu`         | Login                         |
| GitHub OAuth  | `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET` | `/api/oauth/github/callback`                                                      | Import public key from GitHub |

## Deploy in Docker

We recommend to deploy Clustron with docker container.

You can find the docker images on https://hub.docker.com/r/nycusdc/clustron-backend

Tag `stage` for latest released stable version. Tag `dev` for development version.

```yaml
name: clustron

services:
  backend:
    image: nycusdc/clustron-backend:stage # change as needed
    networks:
      - internal
      - traefik
    depends_on:
      postgres:
        condition: service_healthy
      ldap:
        condition: service_healthy
    environment:
      - ENV=stage # change as needed
      - HOST=0.0.0.0
      - GOOGLE_OAUTH_CLIENT_ID=${GOOGLE_OAUTH_CLIENT_ID} # change as needed
      - GOOGLE_OAUTH_CLIENT_SECRET=${GOOGLE_OAUTH_CLIENT_SECRET} # change as needed
      - NYCU_OAUTH_CLIENT_ID=${NYCU_OAUTH_CLIENT_ID} # change as needed
      - NYCU_OAUTH_CLIENT_SECRET=${NYCU_OAUTH_CLIENT_SECRET} # change as needed
      - GITHUB_OAUTH_CLIENT_ID=${GITHUB_OAUTH_CLIENT_ID} # change as needed
      - GITHUB_OAUTH_CLIENT_SECRET=${GITHUB_OAUTH_CLIENT_SECRET} # change as needed
      - SECRET=${SECRET} # change as needed
      - DATABASE_URL=postgres://postgres:password@postgres:5432/clustron?sslmode=disable # change as needed
      - BASE_URL=https://api.stage.clustron.sdc.nycu.club # change as needed
      - SLURM_TOKEN_HELPER_URL=${SLURM_TOKEN_HELPER_URL} # change as needed
      - SLURM_RESTFUL_BASE_URL=${SLURM_RESTFUL_BASE_URL} # change as needed
      - SLURM_RESTFUL_VERSION=v0.0.44
      - MIGRATION_SOURCE=file:///app/migrations
      - CASBIN_POLICY_SOURCE=policy.csv
      - CASBIN_MODEL_SOURCE=model.conf
      - ALLOW_ORIGINS=* # change as needed
      - LDAP_DEBUG=true
      - LDAP_HOST=ldap # change as needed
      - LDAP_PORT=389 # change as needed
      - LDAP_BASE_DN=dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club # change as needed
      - LDAP_BIND_DN=cn=admin,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club # change as needed
      - LDAP_BIND_PWD=password # change as needed
      - OTEL_COLLECTOR_URL=10.140.0.3:4317 # change as needed
      - REDIS_URL=redis:6379 # change as needed
```

## Configuration

The backend can be configured via environment variables, config file and flags.
We recommend to configure with environment variables.

### General

| Variable      | Description                                                                                              | Required |
| ------------- | -------------------------------------------------------------------------------------------------------- | -------- |
| ENV           | Application environment. Will be presented in the log but won't affect any function. Default to `no-env` | No       |
| HOST          | Host address the server binds to                                                                         | Yes      |
| SECRET        | Secret key used for signing JWT tokens                                                                   | Yes      |
| BASE_URL      | Public base URL of the backend API                                                                       | Yes      |
| ALLOW_ORIGINS | Comma-separated list of allowed CORS origins (`*` for all)                                               | Yes      |

### Authentication (OAuth)

| Variable                   | Description                           | Required                                       |
| -------------------------- | ------------------------------------- | ---------------------------------------------- |
| GOOGLE_OAUTH_CLIENT_ID     | Client ID of Google OAuth Service     | Choose one between Google OAuth and NYCU OAuth |
| GOOGLE_OAUTH_CLIENT_SECRET | Client Secret of Google OAuth Service | Choose one between Google OAuth and NYCU OAuth |
| NYCU_OAUTH_CLIENT_ID       | Client ID of NYCU OAuth Service       | Choose one between Google OAuth and NYCU OAuth |
| NYCU_OAUTH_CLIENT_SECRET   | Client Secret of NYCU OAuth Service   | Choose one between Google OAuth and NYCU OAuth |
| GITHUB_OAUTH_CLIENT_ID     | Client ID of GitHub OAuth Service     | No                                             |
| GITHUB_OAUTH_CLIENT_SECRET | Client Secret of GitHub OAuth Service | No                                             |

### Database

| Variable         | Description                                                         | Required |
| ---------------- | ------------------------------------------------------------------- | -------- |
| DATABASE_URL     | PostgreSQL connection string (e.g., `postgres://user:pass@host/db`) | Yes      |
| MIGRATION_SOURCE | Path to database migration files (e.g., `file:///app/migrations`)   | Yes      |

### Authorization

| Variable             | Description                                               | Required |
| -------------------- | --------------------------------------------------------- | -------- |
| CASBIN_POLICY_SOURCE | Path to the Casbin policy file (e.g., `policy.csv`)       | Yes      |
| CASBIN_MODEL_SOURCE  | Path to the Casbin model config file (e.g., `model.conf`) | Yes      |

### LDAP

| Variable      | Description                                        | Required |
| ------------- | -------------------------------------------------- | -------- |
| LDAP_DEBUG    | Enable LDAP debug logging (`true` / `false`)       | No       |
| LDAP_HOST     | Hostname of the LDAP server                        | Yes      |
| LDAP_PORT     | Port of the LDAP server (default: `389`)           | Yes      |
| LDAP_BASE_DN  | Base Distinguished Name for LDAP queries           | Yes      |
| LDAP_BIND_DN  | Distinguished Name used to bind to the LDAP server | Yes      |
| LDAP_BIND_PWD | Password for the LDAP bind DN                      | Yes      |

### Slurm

| Variable               | Description                                        | Required |
| ---------------------- | -------------------------------------------------- | -------- |
| SLURM_TOKEN_HELPER_URL | URL of the Slurm token helper service              | Yes      |
| SLURM_RESTFUL_BASE_URL | Base URL of the Slurm RESTful API node             | Yes      |
| SLURM_RESTFUL_VERSION  | Version of the Slurm RESTful API (e.g., `v0.0.43`) | Yes      |

### Observability

| Variable           | Description                                          | Required |
| ------------------ | ---------------------------------------------------- | -------- |
| OTEL_COLLECTOR_URL | Address of the OpenTelemetry collector (`host:port`) | No       |

### Cache

| Variable  | Description                                     | Required |
| --------- | ----------------------------------------------- | -------- |
| REDIS_URL | Address of the Redis server (e.g., `host:port`) | No       |

# Get Started

## Install Go

Follow the [official installation guide](https://go.dev/doc/install).
Choose version 1.24 if you would like to specify the Go version.

## Clone the repository

Open your terminal and navigate to the directory that you wish to put this project.

And then execute the following command:

```bash
git clone https://github.com/NYCU-SDC/clustron-backend.git
cd  clustron-backend
git fetch
```

## Install necessary dependencies

### Install Go packages

```bash
make prepare
```

Be sure you have `make` installed. You can check by:

```bash
make -v
```

If the result is something like `make command not found`, install `make` before running the above command.

### Install other tools

We use [sqlc](https://sqlc.dev) for database queries generation and [mockery](https://vektra.github.io/mockery/latest/) for mocking.
Please make sure your mockery version is v3.7.0, otherwise the generated mock code will not work with our codebase.

#### MacOS

```bash
brew install sqlc

brew install mockery
brew upgrade mockery
```

#### Go install

```bash
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
go install github.com/vektra/mockery/v3@v3.7.0
```

You can also find more OS-spacific installing methods from the documentation.

## Run the backend

You can simply start the backend service via command:

```bash
make run
```

## Build the backend

To build the backend code into binary, run:

```bash
make build
```

The binary file will be `./bin/backend`.

## Pre-push hook (Optional)

We recommand you enable the pre-push hook if wish to commit to this repository.
This will run checks before the code is pushed to the remote.

The pre-push hook is run via [lefthook](https://lefthook.dev).

### MacOS

```bash
brew install lefthook
```

### Go install

```bash
go install github.com/evilmartians/lefthook@latest
```

You can also find more OS-spacific installing methods from the documentation.

After installed lefthook, update git hook to use lefthook:

```bash
# run at project root
left hook install
```

Then you are good to go!
The pre-push checks will be envoked when you do `git push`.

If the checks didn't pass, the push will be blocked.

To temporary by pass the pre-push check and push:

```bash
git push origin --no-verify
```

To disable pre-push action until re-open it:

```bash
left hook uninstall
```

## Generate Call Graph (flow-chart)

This project uses [go-callvis](https://github.com/ofabry/go-callvis) to visualize Go code execution and function calls.

### Prerequisite

```bash
go install github.com/ofabry/go-callvis@latest
```

### Usage

By default, this command opens an interactive graph in your web browser (press `Ctrl+C` to stop the server).

- Analyze Default Entry Point (`cmd/backend/main.go`):

  ```bash
  make flow-chart
  ```

- Analyze a Specific Module:

  ```bash
  make flow-chart TARGET=./cmd/backend/main.go FOCUS=user
  ```

- Export to Image (No Browser):
  Use `EXTRA_FLAGS` to save the output directly as an SVG or PNG file.
  ```bash
  make flow-chart TARGET=./internal/user FOCUS=user EXTRA_FLAGS="-format svg -file user_flow"
  ```
