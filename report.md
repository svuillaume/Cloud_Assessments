
  # Default (70% unused entitlement threshold)
  python lw_report_gen.py \
    --report CSA_Detailed \
    --format HTML \
    --customer "Customer Name" \
    --author "Your Name"

  # Custom threshold (50% - shows more identities)
  python lw_report_gen.py \
    --report CSA_Detailed \
    --format PDF \
    --customer "Customer Name" \
    --ciem-threshold 50 \
    --alerts-start-time 30:0

  # With caching for testing
  python lw_report_gen.py \
    --report CSA_Detailed \
    --cache-data \
    --customer "Test" \
    --ciem-threshold 90

  Key Features

  - Dynamic Time Ranges: Uses the --alerts-start-time parameter (7/30/90 days)
  - Unified Report: CIEM data appears alongside compliance, vulnerabilities, and alerts
  - Configurable Threshold: Adjust the unused entitlement percentage filter
  - Multi-Cloud: Analyzes AWS, Azure, and GCP identities
  - Both Formats: Works with HTML and PDF output


