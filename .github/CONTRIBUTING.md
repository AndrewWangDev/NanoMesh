# Contributing to NanoMesh

First off, thank you for taking the time to contribute to NanoMesh! Projects like this thrive because of community members and open-source contributors like you.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

### Prerequisites

- **Node.js**: `v20.x` LTS or later
- **npm**: `v9.x` or later
- **Cloudflare Wrangler CLI**: `v3.x` (`npm install -g wrangler`)
- **Modern Browser**: Chrome 113+ or Edge 113+ with WebGPU enabled (for browser node testing)

### Local Development Setup

1. **Fork and Clone**:
   ```bash
   git clone https://github.com/<your-username>/nanomesh.git
   cd nanomesh
   ```

2. **Install Dependencies**:
   ```bash
   npm ci
   ```

3. **Configure Local Environment**:
   Create a `.dev.vars` file in the project root for local testing secrets:
   ```env
   JWT_SECRET="local-dev-jwt-secret-key-32-chars-min"
   TURNSTILE_SECRET_KEY="1x0000000000000000000000000000000AA"
   ADMIN_PASSWORD="local-test-password"
   ```

4. **Run Local Dev Gateway**:
   ```bash
   npm run dev
   ```
   Wrangler will launch the local worker and expose static assets on `http://localhost:8787`.

5. **Type Checking & Static Analysis**:
   ```bash
   npx tsc --noEmit
   ```

## Development Workflow & Branching Strategy

1. **Create a Feature Branch**:
   Create a branch off the latest `master`:
   ```bash
   git checkout -b feat/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

2. **Commit Conventions**:
   We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
   - `feat(...)`: A new feature or capability
   - `fix(...)`: A bug fix or patch
   - `docs(...)`: Documentation only changes
   - `perf(...)`: Performance optimization
   - `refactor(...)`: Code refactoring without behavioral change
   - `test(...)`: Adding or updating test suites
   - `chore(...)`: Maintenance, build pipeline, or tooling updates

3. **Pull Request Guidelines**:
   - Ensure your branch is rebased onto the latest `master`.
   - Run `npx tsc --noEmit` locally and confirm there are **0 errors**.
   - Fill out the provided [Pull Request Template](PULL_REQUEST_TEMPLATE.md).
   - Ensure atomic transactions and fail-closed security properties for any credit settlement or gateway routing changes.
