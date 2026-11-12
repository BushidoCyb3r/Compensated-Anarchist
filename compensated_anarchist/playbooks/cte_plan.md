# Playbook: cyber threat emulation (CTE) plan
Objective: plan an emulation of the adversary the analyst names, on the kind of network we defend, to test whether
our sensors detect it. **Defensive and plans only:** no exploitation, no exploit code, nothing destructive, and the
harness never runs the emulation. The operator runs it, under the rules of engagement, when the analyst decides.

0. **Two inputs from the analyst: the adversary, and the network** (its type, e.g. enterprise Windows/AD, Linux
   servers, cloud, OT/ICS, mixed; or a network map dropped into the case's CTE plans folder, `maps/`: CSV asset
   list, nmap XML, draw.io, Visio .vsdx, or a text description). If the request has both, go straight to step 1 and
   ask nothing else. If one is missing or ambiguous, ask only for that, and wait.
1. **Task cte_planner** with the analyst's words, verbatim, in the brief (the adversary, the network, any map file
   name, and anything else they said: techniques to add, a time window, systems to avoid). It saves the plan
   (`cte_plan_<adversary>.md`) and an ATT&CK Navigator layer to the CTE plans folder.
2. **Present the plan:**
   - the adversary (G-id) and the network assumptions;
   - the steps by phase, with their T-codes;
   - what is not emulated (exploitation and destructive impact) and why;
   - the telemetry gaps (steps no connected sensor would see);
   - the saved files and the planner's questions.
   Remind the analyst that the plan is reviewed and run by their operators, not by the harness.
3. **Only after the analyst says the emulation has run**, with its time window, the systems involved and the
   operators' execution log (the plan has a table for it; without it, a missed step cannot be told from one that was
   not run, so ask for it):
   - task the threat_hunter with the plan's file name, the window, the systems and the log: it reads the plan and
     checks each step for alerts and for its expected artifacts (read-only queries; endpoint collection asks the
     analyst for approval as usual);
   - follow up with the same cte_planner (`subagent_message`) with the hunter's report: it saves the results file
     (`cte_results_<adversary>.md`) with each step detected, partially detected, missed or not run, and updates the
     layer;
   - task the detection_engineer to build detections for the missed steps.
4. If the analyst edits the plan file, the cte_planner reads their changes before its next plan and learns from them.
