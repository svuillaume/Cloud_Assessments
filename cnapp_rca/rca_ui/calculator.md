# FAIR Calculator Suite — Simple Guide

## What Is This Tool?

The FAIR Calculator helps answer one simple question: **"How much is our cloud security risk costing us, and what's it worth to fix?"**

It has three calculators:
1. **Cloud Risk Score** — Is our cloud setup safe? (Score: 0-100)
2. **Financial Risk** — How much money could we lose? (Dollar amount)
3. **FortiCNAPP ROI** — Is FortiCNAPP worth buying? (Cost vs. Savings)

---

## Quick Start Guide

### Step 1: Cloud Risk Score (Tab ①)

**What it does:** Measures how safe your cloud systems are.

**Information you enter:**
- **High Fidelity Alerts** — Number of real security warnings you got (not false alarms)
- **Threat Level** — How dangerous is the current threat environment? (slide from 0-100)
- **Cloud Problems Found** — Number of security issues found (exposed data, weak passwords, misconfigurations, etc.)
- **Asset Importance** — How critical is the system? (production vs. test)
- **Data Sensitivity** — Does it contain customer info, payment data, private records?

**What you get:** A risk score (0-100)
- **0-29:** Safe, monitor regularly
- **30-59:** Medium risk, fix soon
- **60-79:** High risk, fix this week
- **80-100:** Critical, fix immediately

**Example:** Your payment system has 8 security issues, 2 recent attack attempts, and holds customer credit cards.
- Result: **Risk Score = 62 (High)** → You should prioritize fixing this.

---

### Step 2: Financial Risk (Tab ②)

**What it does:** Turns your risk score into a dollar amount — "How much could we lose per year?"

**Information you enter:**
- **Risk Score Values** — Automatically copies from Tab ① (Cloud Risk)
- **Cost if Hacked** — How much money would one breach cost? (Include: repairs, customer notifications, downtime, fines)

**Cost Examples:**
- Small incident (non-critical data): $100K - $500K
- Medium incident (some customer data): $500K - $2M
- Large incident (major customer data breach): $2M - $5M

**What you get:** Annual Loss Amount (ALE)
- Example: "You could lose $228,750 per year if nothing changes"

---

### Step 3: FortiCNAPP ROI (Tab ③)

**What it does:** "If we buy FortiCNAPP security software, will we save money?"

**Information you enter:**
- **Number of Servers** — How many cloud servers do you have? (Starts at 250)
- **Number of Developers** — Optional: Do you want code scanning too?
- **Annual Risk (ALE)** — Automatically copies from Tab ②
- **Annual Growth Rate** — How much does your business grow? (Default: 3.5%)

**What you get:**
- **3-Year Cost** — Total FortiCNAPP price for 3 years
- **Risk Avoided** — How much money you'll save by reducing threats
- **Net Benefit** — Savings minus cost
- **ROI %** — Is it worth it?
- **Payback Period** — How many months before you break even

**Example:**
- FortiCNAPP costs: $300,000 over 3 years
- Risk reduction: $400,000 saved
- **Net Benefit: $100,000 profit**
- **ROI: +33%** (You make money!)

---

## Understanding Each Tab

### Tab ① — Cloud Risk (Safety Check)

Think of this like a house inspection. We're checking:

| What We Check | Real-World Example |
|---|---|
| **Active Threats** | How many attempted break-ins? |
| **Doors & Windows** | How many security holes exist? |
| **Exposure to Hackers** | How easy is it to break in? |
| **What's Inside** | Are valuable things stored here? |
| **Laws & Regulations** | Are we breaking any rules? |

**Result:** A safety score that shows if your cloud is secure.

---

### Tab ② — Financial Risk (Money Risk)

This answers: "If something goes wrong, how much will it hurt financially?"

**Costs included if you get hacked:**
- Paying people to fix the problem
- Notifying customers
- Buying new equipment
- Lost business while systems are down
- Government fines
- Lawyers

**Example:**
- You have a customer database with 50,000 people's info
- If stolen, you must tell them (law requirement) = expensive
- Reputation damage = lost customers
- **Total cost could be $2 million**
- **Annual risk: $228,750** (spread over 3 years)

---

### Tab ③ — FortiCNAPP ROI (Investment Decision)

This answers: "Should we buy FortiCNAPP security software?"

#### How FortiCNAPP Helps

**Faster Problem Finding:** 
- Without it: Takes 24-48 hours to find a problem
- With FortiCNAPP: Takes 4-6 hours (5x faster)
- **Saves:** 30+ hours per incident, ~$7,500 per incident

**Better Prevention:**
- Year 1: Stops 20% of problems
- Year 2: Stops 40% of problems
- Year 3: Stops 55% of problems

#### Three Deployment Options

**Conservative** (Basic Protection)
- Finds misconfigurations and exposed data
- No agents to install
- Good for: Companies with many cloud providers
- Saves: 55% of your risk after 3 years

**Moderate** (Medium Protection)
- All of Conservative, plus workload protection
- Some agents installed on servers
- Good for: Mid-size companies
- Saves: 60% of your risk after 3 years

**Aggressive** (Full Protection)
- All protection including code scanning
- Best for finding application vulnerabilities
- Good for: Large companies with many applications
- Saves: 65% of your risk after 3 years

---

## Real Example: Should We Buy FortiCNAPP?

**Company Profile:**
- 500 cloud servers
- Annual risk (ALE): $250,000
- Business grows 3% per year

**Calculator Results:**

| Item | Amount |
|---|---|
| FortiCNAPP Cost (3 years) | $570,000 |
| Risk Avoided (3 years) | $682,500 |
| **Net Benefit** | **+$112,500** |
| **ROI** | **+20%** |
| **Payback Period** | 18 months |

**Decision:** ✅ **Buy it** — You'll make money and be safer.

---

## How to Use the Calculator

### For Each Tab:

1. **Enter your information** — Fill in what you know, estimates are OK
2. **Click "Calculate"** — The tool does the math
3. **Review results** — Look at the scores/dollars
4. **Click "Click for Details"** — See the math behind the numbers
5. **Go to next tab** — Click the blue button to continue

### Tips:

- **Estimates are OK** — You don't need exact numbers
- **Use defaults** — Default values are industry standard
- **Ask Security Team** — They can help with some inputs
- **Try "What-If"** — Change numbers to see different scenarios

---

## Key Takeaways

### Cloud Risk Tab Shows:
- Is our cloud safe? (0-100 score)
- What needs fixing? (Which systems are risky)

### Financial Risk Tab Shows:
- How much could we lose per year? (Dollar amount)
- Is that acceptable? (Compare to budget)

### ROI Tab Shows:
- Does FortiCNAPP pay for itself? (Yes/No)
- How long until we break even? (Months)
- Which deployment is best? (Conservative/Moderate/Aggressive)

---

## Why This Matters

**Old way:** Security = cost, not profit
- "We spent $100K on security"
- Question: "Why?"
- Answer: "To prevent bad things"

**New way (this calculator):** Security = investment with returns
- "We spent $100K on FortiCNAPP"
- Question: "How much does it save?"
- Answer: "We avoid $300K in breaches, net profit $200K"

**Business Benefit:**
- Managers understand security ROI
- More budget gets approved
- Company stays safer
- Less chance of expensive breaches

---

## Questions & Answers

**Q: What if I don't know a number?**
A: Use the default or ask your Security team. Estimates work fine.

**Q: Can I change numbers and try again?**
A: Yes! Click Reset and try different scenarios.

**Q: What does "Payback Period" mean?**
A: How many months until FortiCNAPP cost is paid back by risk savings. Example: 18 months = in year 2, you're making profit.

**Q: Which deployment should we choose?**
A: Ask Security. Conservative is safer bet for new deployments; Aggressive if you need maximum protection.

**Q: Is this calculator accurate?**
A: It uses industry data from Forrester and real customer experiences. Accuracy depends on your input numbers.

---

## Support

**Questions about the calculator?** Ask your Security or IT team.

**Need help understanding your results?** Schedule time with your security manager.

**Want to try different scenarios?** Just reset and try again — there's no limit!

---

**Version:** 2.0 | **Last Updated:** July 2026 | **Framework:** FAIR (simplified for everyone)
