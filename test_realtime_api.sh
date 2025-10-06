#!/bin/bash

# Test script for Realtime API endpoints
BASE_URL="http://localhost:8080"
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYTQyMTg5NDctNGMzNy00NDQyLTk2YTItYTg0ODQ1M2E3NmE1IiwiZW1haWwiOiJ0YXFpdWRlZW5Ab2ppLm9uZSIsInVzZXJuYW1lIjoiQVRTIiwicGhvbmUiOiIwMjA2MDk1MDI0IiwibWV0YWRhdGEiOnsiZmlyc3RfbmFtZSI6IkFiZHVsYWkiLCJsYXN0X25hbWUiOiJUYXFpdWRlZW4ifSwidG9rZW5fdHlwZSI6ImFjY2VzcyIsImlzcyI6ImdvLWZvcndhcmQiLCJzdWIiOiJhNDIxODk0Ny00YzM3LTQ0NDItOTZhMi1hODQ4NDUzYTc2YTUiLCJleHAiOjE3NTk4NTg4MjEsIm5iZiI6MTc1OTc3MjQyMSwiaWF0IjoxNzU5NzcyNDIxLCJqdGkiOiI4ODFiODI0Mi03OTdkLTQ5Y2UtYjdmNy1hYzgyMDc2NzY5MjUifQ.rlFa3OJLBl1LS2qtjmNIzrtlyF7aXVOWMLPsKYIagto"

echo "Testing Realtime API Endpoints..."
echo "================================="

# Test 1: Create a channel
echo "1. Creating a channel..."
curl -X POST "$BASE_URL/realtime/channels" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "test-channel",
    "max_subscribers": 100,
    "require_auth": true,
    "metadata": {
      "description": "Test channel for API testing"
    }
  }' | jq .

echo -e "\n"

# Test 2: List channels
echo "2. Listing channels..."
curl -X GET "$BASE_URL/realtime/channels" \
  -H "Authorization: Bearer $TOKEN" | jq .

echo -e "\n"

# Test 3: Get specific channel
echo "3. Getting specific channel..."
curl -X GET "$BASE_URL/realtime/channels/test-channel" \
  -H "Authorization: Bearer $TOKEN" | jq .

echo -e "\n"

# Test 4: Broadcast a message
echo "4. Broadcasting a message..."
curl -X POST "$BASE_URL/realtime/channels/test-channel/broadcast" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "type": "message",
    "event": "test_broadcast",
    "payload": {
      "message": "Hello from API test!",
      "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
    }
  }' | jq .

echo -e "\n"

# Test 5: Update presence
echo "5. Updating presence..."
curl -X POST "$BASE_URL/realtime/channels/test-channel/presence" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "state": {
      "status": "online",
      "custom_message": "Testing API",
      "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
    }
  }' | jq .

echo -e "\n"

# Test 6: Get channel presence
echo "6. Getting channel presence..."
curl -X GET "$BASE_URL/realtime/channels/test-channel/presence" \
  -H "Authorization: Bearer $TOKEN" | jq .

echo -e "\n"

# Test 7: Get channel stats
echo "7. Getting channel stats..."
curl -X GET "$BASE_URL/realtime/channels/test-channel/stats" \
  -H "Authorization: Bearer $TOKEN" | jq .

echo -e "\n"

# Test 8: Get system stats
echo "8. Getting system stats..."
curl -X GET "$BASE_URL/realtime/stats" \
  -H "Authorization: Bearer $TOKEN" | jq .

echo -e "\n"

# Test 9: Subscribe to database changes
echo "9. Subscribing to database changes..."
curl -X POST "$BASE_URL/realtime/channels/test-channel/subscribe" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "table": "users",
    "schema": "public",
    "events": ["INSERT", "UPDATE", "DELETE"],
    "columns": ["id", "email", "username"]
  }' | jq .

echo -e "\n"

# Test 10: Get database subscriptions
echo "10. Getting database subscriptions..."
curl -X GET "$BASE_URL/realtime/subscriptions" \
  -H "Authorization: Bearer $TOKEN" | jq .

echo -e "\n"

echo "API testing completed!"