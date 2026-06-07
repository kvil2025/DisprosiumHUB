# Contributing to DisprosiumHUB 🧪

Thank you for your interest in contributing! Here's how you can help.

## 🚀 Getting Started

1. **Fork** the repository
2. **Clone** your fork locally
3. **Create a branch** for your feature: `git checkout -b feature/my-feature`
4. **Make your changes** and test them
5. **Commit** with a clear message: `git commit -m "feat: add my feature"`
6. **Push** to your fork: `git push origin feature/my-feature`
7. **Open a Pull Request** against `main`

## 📋 Development Setup

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/DisprosiumHUB.git
cd DisprosiumHUB

# Setup environment
cp .env.example .env
# Edit .env with your credentials

# Run with Docker
docker compose up -d --build

# Or run locally (for development)
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

## 🎯 Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation only
- `style:` — Formatting, no code change
- `refactor:` — Code restructuring
- `test:` — Adding tests
- `chore:` — Maintenance tasks

## 💡 Ideas for Contributions

- [ ] Add more step types to the Orchestrator (e.g., `http_request`, `email`)
- [ ] Pipeline import/export (JSON)
- [ ] Pipeline templates gallery
- [ ] Scheduled pipeline execution (cron)
- [ ] Multi-language support (i18n)
- [ ] Mobile-optimized responsive layout
- [ ] Dark/Light theme toggle
- [ ] Pipeline execution history & analytics

## 🐛 Reporting Bugs

Open an [Issue](https://github.com/YOUR_USERNAME/DisprosiumHUB/issues) with:
- **Description** of the bug
- **Steps to reproduce**
- **Expected behavior**
- **Screenshots** (if applicable)
- **Environment** (OS, Docker version, browser)

## 📝 Code of Conduct

Be respectful, inclusive, and constructive. We're all here to learn and build.

---

*Built with 🧪 by the community*
