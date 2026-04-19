#!/bin/bash

# Lacework API Query Script

set -e  # Exit on any error

# Configuration
API_KEY=""
KEY_ID=""
BASE_URL=""
ID_HIGH_PRIV="Identities_with_excessive_privileges.json"
ID_ROOT="Root_Identities.json"
ID_ROOTandHIGH="Root_Identities_with_excessive_privileges.json"
OUTPUT_TABLE="Root_Identities_with_excessive_privileges_table.txt"

echo "Starting Lacework API query..."

# Step 1: Get access token
echo "Getting access token..."
TOKEN_RESPONSE=$(curl -s -H "X-LW-UAKS:${API_KEY}" \
     -H "Content-Type: application/json" \
     -X POST \
     -d "{\"keyId\": \"${KEY_ID}\", \"expiryTime\": 3600}" \
     "${BASE_URL}/access/tokens")

# Extract token from response
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.token // .access_token // .data.token')

if [ "$ACCESS_TOKEN" == "null" ] || [ -z "$ACCESS_TOKEN" ]; then
    echo "Error: Failed to get access token"
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi

echo "Access token obtained successfully"

# Step 2: Execute query for AWS identities with high unused entitlements
echo "Executing query for identities with excessive privileges..."
curl -s -X POST "${BASE_URL}/Queries/execute" \
  -H "Authorization: ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "queryText": "{\n  source {\n    LW_CE_IDENTITIES\n  }\n  filter {\n    PROVIDER_TYPE = '\''AWS'\''\n  }\n  return distinct {\n    RECORD_CREATED_TIME,\n    PRINCIPAL_ID,\n    PROVIDER_TYPE,\n    DOMAIN_ID,\n    NAME,\n    LAST_USED_TIME,\n    CREATED_TIME,\n    METRICS,\n    TAGS,\n    ACCESS_KEYS,\n    ACCESS_KEYS_LIST,\n    ENTITLEMENT_COUNTS\n  }\n}"
    },
    "arguments": [
      {
        "name": "StartTimeRange",
        "value": "2024-01-01T00:00:00.000Z"
      },
      {
        "name": "EndTimeRange", 
        "value": "2024-12-31T23:59:59.000Z"
      }
    ]
  }' | jq '.data[] | select(.ENTITLEMENT_COUNTS.entitlements_unused_count >= 70)' > "$ID_HIGH_PRIV"

# Step 3: Execute query for AWS identities with full admin access
echo "Executing query for root identities..."
curl -s -X POST "${BASE_URL}/Queries/execute" \
  -H "Authorization: ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "queryText": "{\n  source {\n    LW_CE_IDENTITIES\n  }\n  filter {\n    PROVIDER_TYPE = '\''AWS'\''\n  }\n  return distinct {\n    RECORD_CREATED_TIME,\n    PRINCIPAL_ID,\n    PROVIDER_TYPE,\n    DOMAIN_ID,\n    NAME,\n    LAST_USED_TIME,\n    CREATED_TIME,\n    METRICS,\n    TAGS,\n    ACCESS_KEYS,\n    ACCESS_KEYS_LIST,\n    ENTITLEMENT_COUNTS\n  }\n}"
    },
    "arguments": [
      {
        "name": "StartTimeRange",
        "value": "2024-01-01T00:00:00.000Z"
      },
      {
        "name": "EndTimeRange",
        "value": "2024-12-31T23:59:59.000Z"
      }
    ]
  }' | jq '.data[] | select(.METRICS.risks[]? == "ALLOWS_FULL_ADMIN")' > "$ID_ROOT"

# Step 4: Execute query for AWS identities with high unused entitlements and full admin access
echo "Executing query for root identities with excessive privileges..."
curl -s -X POST "${BASE_URL}/Queries/execute" \
  -H "Authorization: ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "queryText": "{\n  source {\n    LW_CE_IDENTITIES\n  }\n  filter {\n    PROVIDER_TYPE = '\''AWS'\''\n  }\n  return distinct {\n    RECORD_CREATED_TIME,\n    PRINCIPAL_ID,\n    PROVIDER_TYPE,\n    DOMAIN_ID,\n    NAME,\n    LAST_USED_TIME,\n    CREATED_TIME,\n    METRICS,\n    TAGS,\n    ACCESS_KEYS,\n    ACCESS_KEYS_LIST,\n    ENTITLEMENT_COUNTS\n  }\n}"
    },
    "arguments": [
      {
        "name": "StartTimeRange",
        "value": "2024-01-01T00:00:00.000Z"
      },
      {
        "name": "EndTimeRange",
        "value": "2024-12-31T23:59:59.000Z"
      }
    ]
  }' | jq '.data[] | select(.ENTITLEMENT_COUNTS.entitlements_unused_count >= 70) | select(.METRICS.risks[]? == "ALLOWS_FULL_ADMIN")' > "$ID_ROOTandHIGH"

# Step 5: Create a formatted table output
echo "Creating formatted table output..."
curl -s -X POST "${BASE_URL}/Queries/execute" \
  -H "Authorization: ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "queryText": "{\n  source {\n    LW_CE_IDENTITIES\n  }\n  filter {\n    PROVIDER_TYPE = '\''AWS'\''\n  }\n  return distinct {\n    RECORD_CREATED_TIME,\n    PRINCIPAL_ID,\n    PROVIDER_TYPE,\n    DOMAIN_ID,\n    NAME,\n    LAST_USED_TIME,\n    CREATED_TIME,\n    METRICS,\n    TAGS,\n    ACCESS_KEYS,\n    ACCESS_KEYS_LIST,\n    ENTITLEMENT_COUNTS\n  }\n}"
    },
    "arguments": [
      {
        "name": "StartTimeRange",
        "value": "2024-01-01T00:00:00.000Z"
      },
      {
        "name": "EndTimeRange",
        "value": "2024-12-31T23:59:59.000Z"
      }
    ]
  }' | jq -r '.data[] | select(.ENTITLEMENT_COUNTS.entitlements_unused_count >= 70) | select(.METRICS.risks[]? == "ALLOWS_FULL_ADMIN") | [.PRINCIPAL_ID, .NAME, .PROVIDER_TYPE, .DOMAIN_ID, (.ENTITLEMENT_COUNTS.entitlements_unused_count | tostring), .METRICS.risk_severity] | @tsv' | column -t -s $'\t' > "$OUTPUT_TABLE"

# Check results and display summary
echo ""
echo "=== RESULTS SUMMARY ==="

if [ -f "$ID_HIGH_PRIV" ]; then
    HIGH_PRIV_COUNT=$(jq -s 'length' "$ID_HIGH_PRIV")
    echo "Identities with >= 70 unused entitlements: $HIGH_PRIV_COUNT"
    echo "Results saved to: $ID_HIGH_PRIV"
else
    echo "Error: High privilege identities file was not created"
fi

if [ -f "$ID_ROOT" ]; then
    ROOT_COUNT=$(jq -s 'length' "$ID_ROOT")
    echo "Identities with ALLOWS_FULL_ADMIN: $ROOT_COUNT"
    echo "Results saved to: $ID_ROOT"
else
    echo "Error: Root identities file was not created"
fi

if [ -f "$ID_ROOTandHIGH" ]; then
    COMBINED_COUNT=$(jq -s 'length' "$ID_ROOTandHIGH")
    echo "Identities with >= 70 unused entitlements AND full admin access: $COMBINED_COUNT"
    echo "Results saved to: $ID_ROOTandHIGH"
    echo "Formatted table saved to: $OUTPUT_TABLE"
else
    echo "Error: Combined results file was not created"
fi

echo ""
echo "Query execution completed!"
