# GitHub Actions Workflows

This document explains the CI/CD workflows for the Security Test Framework.

## Workflows

### 1. Docker Compose Security Tests (`docker-compose-tests.yml`)

**Triggers:**
- Push to `main`, `develop`, or `feature/**` branches
- Pull requests to `main` or `develop`

**What it does:**
- Sets up Docker services (DVWA and MariaDB)
- Waits for services to be healthy
- Runs security tests via pytest
- Generates HTML and JSON reports
- Uploads artifacts
- Comments on PRs with test results

**Key Features:**
- Parallel service initialization using GitHub Actions services
- Health checks to ensure services are ready
- Automatic artifact retention (30 days)
- PR comments with test summary
- JUnit XML for integration with GitHub checks

---

### 2. Scheduled Security Tests (`scheduled-tests.yml`)

**Triggers:**
- Daily at 2 AM UTC (configurable via cron)
- Manual trigger via "Run workflow" button

**What it does:**
- Runs comprehensive security tests on a schedule
- Extended artifact retention (90 days)
- Provides summary in job summary

**Configuration:**
Edit the `cron` expression in `scheduled-tests.yml` to change the schedule:
```yaml
on:
  schedule:
    - cron: '0 2 * * *'  # 2 AM UTC daily
```

Common cron examples:
- `'0 2 * * *'` - Daily at 2 AM UTC
- `'0 2 * * 0'` - Weekly on Sunday at 2 AM UTC
- `'0 2 1 * *'` - Monthly on 1st at 2 AM UTC

---

## Setup Instructions

### Prerequisites
- Repository must have GitHub Actions enabled
- Docker login credentials (if using private Docker images)

### Environment Variables
If needed, add environment variables to GitHub:

1. Go to **Settings → Secrets and variables → Actions**
2. Click **New repository secret**
3. Add variables like:
   - `TARGET_URL`: Custom target URL (default: http://localhost:8080)
   - `DOCKER_USERNAME`: For private registries
   - `DOCKER_PASSWORD`: For private registries

### Branch Protection Rules (Optional)
To require passing tests before merge:

1. Go to **Settings → Branches → Branch protection rules**
2. Create rule for `main` and `develop`
3. Check: "Require status checks to pass before merging"
4. Select "Security Test Results" and "Docker Compose Security Tests"

---

## Outputs & Artifacts

### Generated Reports
Each workflow run produces:

- **pytest_report.html** - Detailed test report (viewable in browser)
- **pytest_report.json** - Machine-readable test results
- **junit_results.xml** - JUnit format for CI integration
- **security_report.html** - Security findings summary (if generated)
- **security_results.json** - Structured security test results

### Accessing Artifacts
1. Go to **Actions** tab
2. Click the workflow run
3. Scroll to **Artifacts** section
4. Download `security-reports` ZIP

---

## Monitoring & Alerts

### GitHub Status Checks
- Tests automatically block PR merges if configured
- Red ✗ or green ✓ indicators on commits

### Email Notifications
Configure in **Settings → Notifications** to receive:
- Workflow failures
- Scheduled test results

### Custom Notifications (Advanced)
Add Slack/Teams integration:
```yaml
- name: Notify Slack on failure
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    webhook-url: ${{ secrets.SLACK_WEBHOOK }}
```

---

## Troubleshooting

### Workflow won't start
- [ ] Check `.github/workflows/` files are in correct branch
- [ ] Check GitHub Actions are enabled (Settings → Actions)
- [ ] Verify YAML syntax (use VS Code YAML extension)

### Services fail to start
- [ ] Check Docker image availability: `ghcr.io/digininja/dvwa:latest`
- [ ] Verify MariaDB password matches docker-compose.yml
- [ ] Check port conflicts (8080, 3306)

### Tests timeout
- [ ] Increase `max_attempts` in "Wait for DVWA" step
- [ ] Reduce number of tests in a single run
- [ ] Check GitHub runner resources

### Reports not generated
- [ ] Verify `pytest.ini` configuration
- [ ] Check `scripts/generate_report.py` exists and is executable
- [ ] Check artifacts are being created (download and inspect)

---

## Local Testing

Test locally before pushing:

```bash
# Start services
docker compose up -d

# Wait for DVWA to start (check http://localhost:8080)

# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest security_tests/ -v

# Tear down
docker compose down -v
```

---

## Performance Tips

- Use `continue-on-error: true` to prevent workflow failures
- Cache pip dependencies (already configured)
- Consider splitting tests into parallel jobs for faster runs
- Use workflow concurrency to cancel outdated runs

---

## Advanced Configuration

### Running tests in parallel
```yaml
strategy:
  matrix:
    test-suite: [auth, injection, xss, csrf]
  
  steps:
    - name: Run specific test suite
      run: |
        python -m pytest security_tests/${test_suite}_tests.py -v
```

### Custom Docker build
```yaml
- name: Build custom DVWA image
  run: |
    docker build -t dvwa:custom -f Dockerfile.custom .
```

### Send reports to external storage
```yaml
- name: Upload to S3
  uses: jakejarvis/s3-upload-github-action@master
  with:
    args: --acl public-read --follow-symlinks --delete
  env:
    AWS_S3_BUCKET: ${{ secrets.AWS_S3_BUCKET }}
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

---

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Docker Services in Actions](https://docs.github.com/en/actions/using-containerized-services/about-service-containers)
- [pytest Documentation](https://docs.pytest.org/)
- [cron syntax](https://crontab.guru/)
