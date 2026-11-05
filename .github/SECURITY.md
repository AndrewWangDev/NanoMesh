# Security Policy

NanoMesh takes the security of our distributed AI orchestration runtime and our community seriously. We appreciate your efforts to responsibly disclose vulnerabilities.

## Supported Versions

Only the latest release on the `master` branch receives active security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x (master) | :white_check_mark: |
| < 1.0.0 | :x:                |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues, discussions, or social channels.**

Instead, please report potential security vulnerabilities through one of the following private channels:

1. **GitHub Private Vulnerability Reporting (Recommended)**:  
   Navigate to the **Security** tab of this repository, click **Advisories**, and then click **Report a vulnerability**.
2. **Security Contact Email**:  
   Send details and reproduction steps to:
   - **Email**: `me@andrewwangdev.com`
   - **Subject**: `[SECURITY VULNERABILITY] NanoMesh - <Brief Summary>`

### What to Include in Your Report

To help us triage and resolve the issue efficiently, please include:
- A clear description of the vulnerability and its potential impact.
- Step-by-step reproduction instructions or a minimal Proof of Concept (PoC).
- The affected component (e.g., Gateway WebAuthn, Edge Dispatcher, WebGPU Browser Engine, D1 Settlement).
- Any proposed remediations or patches if available.

## Our Security Response Process

- **Acknowledgement & Triage**: We strive to acknowledge receipt of your vulnerability report as soon as possible. Rather than committing to rigid arbitrary timeframes (such as 24 or 48 hours), our maintainers prioritize and investigate confirmed vulnerabilities promptly and thoroughly.
- **Coordination & Patching**: Once confirmed, a fix will be developed and verified in a private security fork.
- **Responsible Disclosure**: A public Security Advisory and CVE (if applicable) will be published alongside the patch release. We will gladly credit the reporter in release notes unless requested to remain anonymous.

Thank you for helping keep NanoMesh and its users safe!
