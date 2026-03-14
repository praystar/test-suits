// ============================================================
// Security Test Integration Framework — Jenkinsfile
// Declarative Pipeline for automated security test execution
// ============================================================

pipeline {
    agent {
        docker {
            image 'python:3.12-slim'
            args '''
                --shm-size=2g
                -v /dev/shm:/dev/shm
                -e DISPLAY=:99
            '''
        }
    }

    // ─── Pipeline Parameters ────────────────────────────────
    parameters {
        string(
            name: 'TARGET_URL',
            defaultValue: 'http://localhost:8080',
            description: 'Base URL of the application under test'
        )
        booleanParam(
            name: 'HEADLESS',
            defaultValue: true,
            description: 'Run browser in headless mode'
        )
        choice(
            name: 'TEST_SUITE',
            choices: ['all', 'xss', 'sqli', 'auth', 'csrf_headers'],
            description: 'Which security test suite to run'
        )
        booleanParam(
            name: 'FAIL_ON_WARNINGS',
            defaultValue: false,
            description: 'Treat WARN results as build failures'
        )
        string(
            name: 'SLACK_CHANNEL',
            defaultValue: '#security-alerts',
            description: 'Slack channel for security notifications'
        )
    }

    // ─── Environment Variables ───────────────────────────────
    environment {
        TARGET_URL      = "${params.TARGET_URL}"
        HEADLESS        = "${params.HEADLESS}"
        TEST_SUITE      = "${params.TEST_SUITE}"
        REPORT_DIR      = "reports"
        RESULTS_FILE    = "reports/security_results.json"
        HTML_REPORT     = "reports/security_report.html"
        JUNIT_REPORT    = "reports/junit_results.xml"
        SELENIUM_TIMEOUT = "15"
        PYTHONDONTWRITEBYTECODE = "1"
    }

    // ─── Pipeline Options ────────────────────────────────────
    options {
        timeout(time: 45, unit: 'MINUTES')
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '30'))
        ansiColor('xterm')
    }

    stages {

        // ─── Stage 1: Environment Setup ──────────────────────
        stage('Setup Environment') {
            steps {
                echo "🔧 Setting up security test environment..."
                sh '''
                    apt-get update -qq
                    apt-get install -y -qq \
                        wget \
                        gnupg \
                        unzip \
                        xvfb \
                        libglib2.0-0 \
                        libnss3 \
                        libgconf-2-4 \
                        libfontconfig1 \
                        chromium \
                        chromium-driver \
                        2>/dev/null

                    echo "Chrome version: $(chromium --version 2>/dev/null || echo 'not found')"
                    echo "ChromeDriver version: $(chromedriver --version 2>/dev/null || echo 'not found')"
                '''

                sh '''
                    pip install --quiet --upgrade pip
                    pip install --quiet \
                        selenium>=4.18.0 \
                        requests>=2.31.0 \
                        pytest>=8.0.0 \
                        pytest-html>=4.1.0 \
                        pytest-json-report>=1.5.0 \
                        junit-xml>=1.9 \
                        colorlog>=6.8.0

                    echo "✅ Dependencies installed"
                    python -c "import selenium; print(f'Selenium: {selenium.__version__}')"
                '''

                sh 'mkdir -p ${REPORT_DIR}'

                echo "🎯 Target URL: ${TARGET_URL}"
                echo "🧪 Test Suite: ${TEST_SUITE}"
            }
        }

        // ─── Stage 2: Pre-Flight Checks ──────────────────────
        stage('Pre-Flight Checks') {
            steps {
                echo "🛫 Running pre-flight checks..."
                sh '''
                    echo "=== Target Connectivity ==="
                    curl -sSf --max-time 10 "${TARGET_URL}" > /dev/null && \
                        echo "✅ Target is reachable" || \
                        echo "⚠️  Target may not be reachable — tests may fail"

                    echo ""
                    echo "=== SSL/TLS Check ==="
                    if echo "${TARGET_URL}" | grep -q "^https"; then
                        curl -sSf --max-time 10 \
                            -w "SSL: %{ssl_verify_result} | Protocol: %{ssl_version}\\n" \
                            "${TARGET_URL}" > /dev/null || true
                    else
                        echo "⚠️  HTTP-only target — no SSL/TLS to verify"
                    fi

                    echo ""
                    echo "=== Response Headers Preview ==="
                    curl -sI --max-time 10 "${TARGET_URL}" | head -20 || true
                '''
            }
        }

        // ─── Stage 3: XSS Tests ──────────────────────────────
        stage('XSS Security Tests') {
            when {
                anyOf {
                    expression { params.TEST_SUITE == 'all' }
                    expression { params.TEST_SUITE == 'xss' }
                }
            }
            steps {
                echo "🔍 Running XSS security tests..."
                sh '''
                    Xvfb :99 -screen 0 1920x1080x24 &
                    XVFB_PID=$!

                    python -m pytest \
                        security_tests/xss_tests.py \
                        -v \
                        --tb=short \
                        --junit-xml=${REPORT_DIR}/xss_junit.xml \
                        --html=${REPORT_DIR}/xss_report.html \
                        --self-contained-html \
                        -k "xss" \
                        || true

                    kill $XVFB_PID 2>/dev/null || true
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/xss_junit.xml'
                }
            }
        }

        // ─── Stage 4: SQL Injection Tests ────────────────────
        stage('SQL Injection Tests') {
            when {
                anyOf {
                    expression { params.TEST_SUITE == 'all' }
                    expression { params.TEST_SUITE == 'sqli' }
                }
            }
            steps {
                echo "💉 Running SQL injection tests..."
                sh '''
                    Xvfb :99 -screen 0 1920x1080x24 &
                    XVFB_PID=$!

                    python -m pytest \
                        security_tests/sql_injection_tests.py \
                        -v \
                        --tb=short \
                        --junit-xml=${REPORT_DIR}/sqli_junit.xml \
                        --html=${REPORT_DIR}/sqli_report.html \
                        --self-contained-html \
                        || true

                    kill $XVFB_PID 2>/dev/null || true
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/sqli_junit.xml'
                }
            }
        }

        // ─── Stage 5: Authentication Tests ───────────────────
        stage('Authentication Security Tests') {
            when {
                anyOf {
                    expression { params.TEST_SUITE == 'all' }
                    expression { params.TEST_SUITE == 'auth' }
                }
            }
            steps {
                echo "🔐 Running authentication security tests..."
                sh '''
                    Xvfb :99 -screen 0 1920x1080x24 &
                    XVFB_PID=$!

                    python -m pytest \
                        security_tests/auth_tests.py \
                        -v \
                        --tb=short \
                        --junit-xml=${REPORT_DIR}/auth_junit.xml \
                        --html=${REPORT_DIR}/auth_report.html \
                        --self-contained-html \
                        || true

                    kill $XVFB_PID 2>/dev/null || true
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/auth_junit.xml'
                }
            }
        }

        // ─── Stage 6: CSRF & Headers Tests ───────────────────
        stage('CSRF & Headers Tests') {
            when {
                anyOf {
                    expression { params.TEST_SUITE == 'all' }
                    expression { params.TEST_SUITE == 'csrf_headers' }
                }
            }
            steps {
                echo "🛡️  Running CSRF and security headers tests..."
                sh '''
                    Xvfb :99 -screen 0 1920x1080x24 &
                    XVFB_PID=$!

                    python -m pytest \
                        security_tests/csrf_and_headers_tests.py \
                        -v \
                        --tb=short \
                        --junit-xml=${REPORT_DIR}/csrf_junit.xml \
                        --html=${REPORT_DIR}/csrf_report.html \
                        --self-contained-html \
                        || true

                    kill $XVFB_PID 2>/dev/null || true
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/csrf_junit.xml'
                }
            }
        }

        // ─── Stage 7: Report Generation ──────────────────────
        stage('Generate Security Report') {
            steps {
                echo "📊 Generating consolidated security report..."
                sh '''
                    python scripts/generate_report.py \
                        --results ${RESULTS_FILE} \
                        --output ${HTML_REPORT} \
                        --build-url "${BUILD_URL}" \
                        --build-number "${BUILD_NUMBER}" \
                        --target-url "${TARGET_URL}" \
                        || echo "Warning: Report generation failed"
                '''
            }
        }

        // ─── Stage 8: Threshold Evaluation ───────────────────
        stage('Evaluate Security Thresholds') {
            steps {
                echo "⚖️  Evaluating security thresholds..."
                script {
                    def exitCode = sh(
                        script: '''
                            python scripts/evaluate_thresholds.py \
                                --results ${RESULTS_FILE} \
                                --fail-on-critical true \
                                --fail-on-high true \
                                --fail-on-warnings ${FAIL_ON_WARNINGS}
                        ''',
                        returnStatus: true
                    )

                    if (exitCode == 2) {
                        currentBuild.result = 'UNSTABLE'
                        echo "⚠️  Security warnings found — build marked UNSTABLE"
                    } else if (exitCode != 0) {
                        currentBuild.result = 'FAILURE'
                        error("❌ Critical/High security vulnerabilities found — build FAILED")
                    } else {
                        echo "✅ All security thresholds passed"
                    }
                }
            }
        }
    }

    // ─── Post-Pipeline Actions ────────────────────────────────
    post {
        always {
            echo "📁 Archiving security artifacts..."
            archiveArtifacts(
                artifacts: 'reports/**/*',
                allowEmptyArchive: true,
                fingerprint: true
            )

            publishHTML(target: [
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'reports',
                reportFiles: 'security_report.html',
                reportName: 'Security Test Report',
                reportTitles: 'Security Test Results'
            ])
        }

        failure {
            echo "🚨 Security tests FAILED — notifying team"
            emailext(
                subject: "[SECURITY] Build #${BUILD_NUMBER} — Vulnerabilities Found — ${TARGET_URL}",
                body: """
                    Security test suite has detected vulnerabilities.

                    Build:  #${BUILD_NUMBER}
                    Target: ${TARGET_URL}
                    Result: ${currentBuild.result}
                    URL:    ${BUILD_URL}

                    Please review the attached security report immediately.
                """,
                to: '${DEFAULT_RECIPIENTS}',
                attachmentsPattern: 'reports/security_report.html'
            )
        }

        unstable {
            echo "⚠️  Security tests completed with WARNINGS"
        }

        success {
            echo "✅ Security tests PASSED — no vulnerabilities detected"
        }

        cleanup {
            sh 'pkill -f "Xvfb" 2>/dev/null || true'
            cleanWs()
        }
    }
}
