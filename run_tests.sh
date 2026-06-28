#!/bin/bash

echo "=========================================="
echo "Flash512-Vanguard Test Suite"
echo "=========================================="

# Run all tests with coverage
pytest tests/ -v --cov=flash512 --cov-report=term-missing

# Check exit code
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ All tests passed!"
    echo ""
else
    echo ""
    echo "❌ Some tests failed!"
    echo ""
    exit 1
fi