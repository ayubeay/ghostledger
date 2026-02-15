#!/bin/bash
# Submit test claims to trigger Signal Scouts pattern detection
# Run: bash ~/GhostLedger/test_signals.sh

API="http://localhost:8081/v1/intake/submissions"

echo "📡 Submitting test claims to trigger Signal Scouts..."
echo ""

# Claim 1: Another Shiftsmart claim (will cluster with existing)
echo "1/3 — Shiftsmart claim (Marcus Johnson)..."
curl -s -X POST "$API" \
  -H "Content-Type: application/json" \
  -d '{
    "full_name": "Marcus Johnson",
    "email": "marcus.j@testmail.com",
    "platform_or_company": "Shiftsmart",
    "estimated_amount_usd": 1840.00,
    "platform_reason": "Completed 3 weeks of shifts, payout withheld after account flagged for no reason",
    "contacted_support": "Yes, but no resolution",
    "referral_source": "Reddit",
    "authorization": true
  }' | python3 -m json.tool
echo ""

# Claim 2: Third Shiftsmart claim (now 3 = alert level)
echo "2/3 — Shiftsmart claim (Aisha Williams)..."
curl -s -X POST "$API" \
  -H "Content-Type: application/json" \
  -d '{
    "full_name": "Aisha Williams",
    "email": "aisha.w@testmail.com",
    "platform_or_company": "Shiftsmart",
    "estimated_amount_usd": 2250.00,
    "platform_reason": "Payment pending for over 30 days after completing shifts. Support keeps saying they are reviewing.",
    "contacted_support": "Yes, still waiting",
    "referral_source": "TikTok",
    "authorization": true
  }' | python3 -m json.tool
echo ""

# Claim 3: A Stripe claim with unusually high amount (will trigger amount anomaly)
echo "3/3 — Stripe claim (David Chen, high value)..."
curl -s -X POST "$API" \
  -H "Content-Type: application/json" \
  -d '{
    "full_name": "David Chen",
    "email": "david.chen@testmail.com",
    "platform_or_company": "Stripe",
    "estimated_amount_usd": 47500.00,
    "platform_reason": "Stripe froze merchant account and is holding entire reserve balance. No explanation given. Business cannot operate.",
    "contacted_support": "Yes, but no resolution",
    "referral_source": "Twitter / X",
    "authorization": true
  }' | python3 -m json.tool

echo ""
echo "✅ Done! Now go to http://localhost:8081 → Signals tab → Click 'Scan Now'"
echo "   You should see:"
echo "   • Respondent Cluster: Shiftsmart (3+ claims)"
echo "   • Harm Concentration: Shiftsmart payout withholding"
echo "   • Velocity Spike: 3+ claims in 7 days vs Shiftsmart"
echo "   • Possibly Amount Anomaly for David Chen's $47,500 claim"
