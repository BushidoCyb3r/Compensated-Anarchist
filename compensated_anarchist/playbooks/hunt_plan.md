# Playbook: ATT&CK hunt plan (named actors or techniques)
Objective: design a hunt plan from MITRE ATT&CK for the actors or techniques below, then hunt only when the analyst
says so. Planning and hunting are separate jobs:
- **hunt_planner** designs the plan. It never runs hunt queries.
- **threat_hunter** executes the plan, after the analyst approves it.

0. **Always check with the analyst first.** Before tasking anyone, and before anything looks at the connected
   systems, ask how they want the plan built. If their request already covers some of the points, confirm those in
   one line and ask the rest. Ask once, briefly, with defaults they can accept by replying "default":
   1. How to build it:
      - (a) from their input only, without looking at the connected systems;
      - (b) survey the connected systems (platforms, data sources, fields) and recommend the best plan;
      - (c) both: start from their input, then tailor it to what the systems can see. **Default: (c).**
   2. Actors (names, aliases or G-ids) and/or specific T-codes. If they have none, a sector, region or concern to
      start from.
   3. Platforms to cover. Default: what the environment has.
   4. Which tools to write queries for. Default: every connected tool.
   5. How many hunts to prioritize (default 15), and the hunt window for the threat_hunter (default 30 days).
   6. Include techniques reached through the actors' software and attributed campaigns? Default: yes.
   Then stop and wait for the answer.
1. **Task hunt_planner** with the analyst's answers, word for word, in the brief. It saves the plan
   (`hunt_plan_<actors>.md`) and an ATT&CK Navigator layer to the case's hunt plans folder, where the threat_hunter
   looks for plans.
2. **Present the plan:**
   - how it was built;
   - the top hunts with their T-codes and data status;
   - the telemetry gaps;
   - where the files were saved.
   Ask whether to hunt now, and over which window.
3. **Only on the analyst's go-ahead:**
   - threat_hunter executes the plan. Name the plan in its brief: it finds and reads it in the hunt plans folder
     with `hunt_plan_list` / `hunt_plan_read`, and saves its results next to it. It never starts a plan without
     the analyst's go-ahead.
     Endpoint collection asks the analyst for approval as usual.
   - Present the results: the outcome per hunt (hits / clear / query_error / inconclusive) with its evidence, the
     queries the hunter had to correct, and the gaps. A hunt is `clear` only if its data was there for the window.
   - Confirmed activity: tell the analyst at once and recommend the incident response playbook.
   - detection_engineer turns hunts that found signal into back-tested detections.
   - The hunter's corrections go back to the same hunt_planner (`subagent_message`) when the analyst wants the plan
     revised: it fixes the queries and re-ranks for the next round.
