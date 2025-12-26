*prompt* i want to learn more about antigravity. attached is the scope/guidelines of a real bug bounty program. what needs to happen next?

To use Google Antigravity effectively for the SEEK Bug Bounty program, you must transition from a traditional "assistant" workflow to an agentic "orchestration" workflow. Antigravity is an agent-first development platform (IDE) released in late 2025 alongside Gemini 3. It allows you to deploy autonomous agents that can plan, execute terminal commands, and control a browser to perform end-to-end security tasks.

Based on the SEEK scope you provided, here is exactly what needs to happen next to set up your mission.

### 1. Grounding the Agent in the "Rules of Engagement"

SEEK has very strict requirements that an autonomous agent might accidentally violate if not properly constrained. You must create a Workspace Rule in Antigravity to prevent account bans or disqualification.

* Email Enforcement: Instruct the agent to *only* use your `@bugcrowdninja.com` email for all account creation and testing on domains like `seek.com.au` or `seekpass.co`.
* Rate-Limiting & DoS: Explicitly forbid the agent from performing automated scanning or "volume-related" attacks, as these are strictly out of scope for SEEK.
* Target Guardrails: Define the specific allowed targets (e.g., `*.seek.com.au`, `*.sol-data.com`) so the agent does not wander into out-of-scope third-party services.

### 2. Configure the "Agent Manager" for Reconnaissance

Antigravity's Manager View (Mission Control) allows you to spawn multiple agents asynchronously. You should dispatch specialized agents for different parts of the SEEK ecosystem:

* Agent 1 (Mobile Specialist): Task it with analyzing the provided iOS and Android application binaries for the main SEEK app and SEEK Pass.
* Agent 2 (API/GraphQL Specialist): Task it with exploring `graphql.seek.com` and `auth.seek.com` to map authentication flows.
* Agent 3 (Infrastructure Specialist): Have it audit the `*.skinfra.xyz` and `*.outfra.xyz` corporate services that are meant for employee use but are in scope.

### 3. Deploy the "Browser Agent" for UI/UX Auditing

The Browser-in-the-Loop feature is the most powerful tool for this mission. You can command an agent to:

1. Open the Antigravity-linked Chrome browser and navigate to `talent.seek.com.au`.
2. Follow the "Rules for posting a job" automatically: setting the location to Iceland and the category to "Farming" to avoid affecting real users.
3. Attempt to identify IDOR (Insecure Direct Object Reference) vulnerabilities by analyzing how the browser handles user profile data.

### 4. Reviewing "Artifacts" Instead of Raw Logs

As the agents work, they will produce Artifacts—verifiable proof of their activities.

* Task Lists & Plans: Review the agent's strategy before it begins any potentially intrusive testing.
* Browser Recordings: If an agent claims to have bypassed a login on `seekpass-staging.com`, you can watch the video recording of the browser session to verify the vulnerability without repeating the steps yourself.
* Implementation Reports: If a vulnerability is found, ask the agent to generate an Attack Scenario and Recommended Fix artifact in the exact format SEEK requires for a reward.

### Summary Checklist

| Step | Action | Why? |
| --- | --- | --- |
| Workspace | Create a local folder for the SEEK project and open it in Antigravity. | To keep all logs, code, and artifacts isolated. |
| Credentials | Add your `@bugcrowdninja.com` details to the agent's "Knowledge Items". | Ensures the agent uses the correct ID for all interactions. |
| Rate Limit | Set the Review Policy to "Request Review" for terminal commands. | Prevents the agent from accidentally running a banned automated scanner. |

*Would you like me to help you write the specific "Agent Mission" prompt for the SEEK Pass verification flow?*

To set up an autonomous agent in Google Antigravity for the SEEK Pass verification flow, you will use the Agent Manager to dispatch a mission that leverages the platform's integrated browser and terminal.

Follow these steps to configure your mission prompt and workspace rules.

### 1. Define Local Project Rules (`.agent/rules.md`)

Before launching the agent, create a rule file in your workspace to enforce SEEK's specific constraints. This acts as a permanent "instruction set" that the agent must evaluate before any action.

```markdown
# SEEK Pass Testing Rules
- Identity: Always use the @bugcrowdninja.com email for accounts.
- No Automation: Do not use external high-volume scanners (e.g., automated SQLmap or Nuclei).
- OAuth Safety: If a data-sharing flow is triggered between SEEK and SEEK Pass, observe the token exchange but do not intercept tokens belonging to other users.
- Data Integrity: Use fictional document images for verification; do not use real PII.

```

### 2. Configure the Agent's Environment

In the Agent Manager (Mission Control), set the following policies to maintain control while allowing autonomy:

* Mode: Select Agent-assisted development to keep a "human-in-the-loop" for critical logic jumps.
* Terminal Policy: Set to Auto for safe commands (like `ls` or `grep`).
* Review Policy: Set to Agent Decides so it only pings you when it encounters a complex decision.

### 3. The "Mission Mission" Prompt

Paste the following into the Task Composer in the Agent Manager. This prompt is structured for Gemini 3 Pro to trigger its planning and browser sub-agents.

> Mission Objective: > "Analyze the SEEK Pass verification and sharing flow located at `*.seekpass.co`.
> Step 1: Use the browser sub-agent to navigate to the sign-up page. Create a test account using my @bugcrowdninja.com email.
> Step 2: Initiate the document verification flow. Use dummy document artifacts from the `./test-assets` folder.
> Step 3: Trigger the OAuth flow to share results with a main SEEK account. Capture and analyze the redirect URI and state parameters for potential CSRF or open redirection.
> Step 4: Monitor the terminal for any clear-text sensitive data in the console or network logs.
> Deliverable: Generate a Walkthrough Artifact including a screen recording of the OAuth handshake and a report of any anomalous parameter handling."

### 4. What Happens Next?

Once you click "Start," Antigravity will initiate its Agentic Pentesting Cycle:

1. Task Checklist: The agent will generate a step-by-step checklist of how it intends to test the flow.
2. Implementation Plan: It will draft a technical plan detailing which browser actions it will take and which logs it will monitor.
3. Autonomous Execution: The browser will launch with a visible "glow," indicating the agent is clicking and navigating the SEEK Pass UI.
4. Verification: The agent will record a Walkthrough Video of the process, saving it to your artifacts directory for you to review and submit to Bugcrowd.

*Would you like me to help you create a specific "Attack Scenario" template for your first finding report?*
