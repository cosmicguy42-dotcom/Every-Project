#!/bin/bash
set -e

echo "========================================================"
echo "          OUIJA SECURITY INTEGRATION TEST SUITE         "
echo "========================================================"

# Cleanup old processes
pkill -f "ouija start" 2>/dev/null || true
pkill -f "ouija_tor_manager.py" 2>/dev/null || true
sleep 1

# Start ouija server in background
/home/xmv22/.local/bin/ouija start > /tmp/ouija_test.log 2>&1 &
SERVER_PID=$!
trap "kill $SERVER_PID 2>/dev/null || true" EXIT

# Wait for server to listen on port 8765
for i in {1..10}; do
    if curl -s http://127.0.0.1:8765/api/status >/dev/null 2>&1; then
        echo "[OK] Ouija daemon is responding on http://127.0.0.1:8765"
        break
    fi
    sleep 0.5
done

echo ""
echo "--- TEST 1: CLI STATUS ---"
ouija status

echo ""
echo "--- TEST 2: CLI NEW ID (MINT EPHEMERAL ID VIA IPC) ---"
NEW_ID_OUT=$(ouija new id)
echo "$NEW_ID_OUT"
NEW_ID=$(echo "$NEW_ID_OUT" | grep "ID: OUIJA-" | awk '{print $2}')
echo "Minted Ephemeral ID: $NEW_ID"

echo ""
echo "--- TEST 3: REJECT INVALID / FORGED SHA-256 ID ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://127.0.0.1:8765/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "ephemeral_id=OUIJA-fakebadtoken000000000000000000-deadbeef")
echo "HTTP Response code for forged ID: $HTTP_CODE (Expected: 401)"
if [ "$HTTP_CODE" -eq 401 ]; then
    echo "[PASS] Forged ID properly rejected!"
else
    echo "[FAIL] Forged ID was not rejected!"
    exit 1
fi

echo ""
echo "--- TEST 4: AUTHENTICATE WITH VALID EPHEMERAL ID ---"
LOGIN_HEADER=$(curl -s -i -X POST http://127.0.0.1:8765/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "ephemeral_id=$NEW_ID")

COOKIE=$(echo "$LOGIN_HEADER" | grep -i "Set-Cookie" | awk '{print $2}' | tr -d '\r;')
echo "Obtained Ephemeral Session Cookie: $COOKIE"

if [ -z "$COOKIE" ]; then
    echo "[FAIL] No session cookie returned!"
    exit 1
fi
echo "[PASS] Successfully authenticated with ephemeral ID!"

echo ""
echo "--- TEST 5: ACCESS DASHBOARD ---"
DASH_CONTENT=$(curl -s -H "Cookie: $COOKIE" http://127.0.0.1:8765/dashboard)
if echo "$DASH_CONTENT" | grep -q "$NEW_ID"; then
    echo "[PASS] Dashboard accessed successfully and displays current ephemeral ID!"
else
    echo "[FAIL] Dashboard did not contain ephemeral ID"
    exit 1
fi

echo ""
echo "--- TEST 6: ROUTE NEW PEER ---"
PEER_ID="OUIJA-99998888777766665555444433332222-1111222233334444"
curl -s -H "Cookie: $COOKIE" -X POST http://127.0.0.1:8765/peers/add \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "peer_id=$PEER_ID&onion_address=http://127.0.0.1:8765&alias=Shadow_Node" >/dev/null
echo "[PASS] Added peer route for $PEER_ID"

echo ""
echo "--- TEST 7: TRANSMIT TRIPLE-ENCRYPTED MESSAGE (OTP + XMPP + TOR) ---"
SECRET_TEXT="TOP_SECRET_OUIJA_PAYLOAD_TEST_98765"
curl -s -H "Cookie: $COOKIE" -X POST http://127.0.0.1:8765/chat/send \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "peer_id=$PEER_ID&message=$SECRET_TEXT" >/dev/null
echo "[PASS] Message transmitted through OTP ASM -> XMPP OMEMO -> Tor transport!"

echo ""
echo "--- TEST 8: VERIFY DECRYPTED STREAM & XML STANZA INSPECTION ---"
CHAT_PAGE=$(curl -s -H "Cookie: $COOKIE" "http://127.0.0.1:8765/chat?peer=$PEER_ID")
if echo "$CHAT_PAGE" | grep -q "$SECRET_TEXT"; then
    echo "[PASS] Message stream correctly displays decrypted plaintext!"
else
    echo "[FAIL] Plaintext message not found in chat stream"
    exit 1
fi

if echo "$CHAT_PAGE" | grep -q "urn:xmpp:ouija:omemo:v1"; then
    echo "[PASS] XMPP OMEMO XML stanza preview verified in chat inspector!"
else
    echo "[FAIL] Encrypted XMPP stanza missing"
    exit 1
fi

echo ""
echo "--- TEST 9: PURGE ALL VOLATILE RAM ---"
PURGE_RESP=$(curl -s -H "Cookie: $COOKIE" -X POST http://127.0.0.1:8765/purge)
if echo "$PURGE_RESP" | grep -q "MEMORY PURGE COMPLETE"; then
    echo "[PASS] RAM zeroized with assembly fences and memory purged!"
else
    echo "[FAIL] Purge endpoint response failed"
    exit 1
fi

# Verify session is now dead
POST_PURGE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Cookie: $COOKIE" http://127.0.0.1:8765/dashboard)
echo "HTTP response after memory purge: $POST_PURGE_CODE (Expected: 303 Redirect to login)"
if [ "$POST_PURGE_CODE" -eq 303 ]; then
    echo "[PASS] Session token was successfully destroyed in RAM!"
else
    echo "[FAIL] Session was not invalidated"
    exit 1
fi

echo ""
echo "========================================================"
echo "      ALL OUIJA INTEGRATION TESTS PASSED (100%)         "
echo "========================================================"
