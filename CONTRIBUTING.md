# Contributing to SecuriSphere

Thank you for your interest in improving SecuriSphere! We welcome contributions from the community.

## Getting Started

1.  **Fork the Repository**: Click the "Fork" button on GitHub.
2.  **Clone your Fork**:
    ```bash
    git clone https://github.com/YOUR_USERNAME/securisphere.git
    cd securisphere
    ```
3.  **Set Up Environment**: Follow the [Quick Start](README.md#quick-start) in the README.

## Development Workflow

1.  **Create a Branch**: Use a descriptive name for your feature or fix.
    ```bash
    git checkout -b feature/add-new-rule
    ```
2.  **Make Changes**: Implement your code.
3.  **Test**:
    - Run the full stack: `make start`
    - Run integration tests: `make test-integration`
    - Verify with the simulator: `make attack-all`
4.  **Commit**: Use clear, present-tense commit messages.
    ```bash
    git commit -m "Add correlation rule for ransomware detection"
    ```
5.  **Push**: `git push origin feature/add-new-rule`
6.  **Pull Request**: Open a PR on the main repository.

## Project Structure Standards

-   **Monitors**: Place new monitors in `monitors/<service_name>`.
-   **Engine**: Correlation rules go in `engine/correlation/correlation_engine.py`.
-   **Dashboard**: React components go in `frontend/src/components`.

## Coding Guidelines

-   **Python**: Follow PEP 8. Use typing where possible.
-   **JavaScript**: Use ES6+ features.
-   **Logging**: Use the standard logging format defined in existing services.

## Reporting Issues

Please use the GitHub Issues tab to report bugs. Include:
-   Steps to reproduce.
-   Expected vs. Actual behavior.
-   Logs or screenshots.

Thank you for helping make SecuriSphere better!
