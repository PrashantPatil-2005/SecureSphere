#!/bin/bash

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     SecuriSphere Full Evaluation Suite           ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

echo "[1] Check all services are running..."
bash scripts/health_check.sh
if [ $? -ne 0 ]; then
    echo "ERROR: Not all services are healthy. Fix issues before evaluation."
    exit 1
fi

echo ""
echo "[2] Running integration tests..."
pip install -r evaluation/requirements.txt -q
python -m pytest tests/test_integration.py -v
INTEGRATION_RESULT=$?

echo ""
echo "[3] Running full evaluation..."
python evaluation/run_evaluation.py
EVAL_RESULT=$?

echo ""
echo "════════════════════════════════════════════════════"
echo "  Evaluation Complete"
echo "════════════════════════════════════════════════════"
echo ""
echo "  Integration Tests: $([ $INTEGRATION_RESULT -eq 0 ] && echo '✅ PASSED' || echo '❌ FAILED')"
echo "  Evaluation:        $([ $EVAL_RESULT -eq 0 ] && echo '✅ COMPLETED' || echo '❌ ERRORS')"
echo ""
echo "  Results saved to:"
echo "    evaluation/results/"
echo ""
echo "  Dashboard: http://localhost:3000"
echo "════════════════════════════════════════════════════"
