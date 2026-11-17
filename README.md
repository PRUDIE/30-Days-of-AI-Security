# 30 Days of Building in AI Security

Hi, I'm a Security Engineer with over 5 years of experience (vulnerability management, verification of fixes, pentesting, bug bounty), and I'm documenting my journey to understanding AI and how to secure it.

Every day I:

- **Learn** one concept well enough to explain it in simple terms
- **Build** something that demonstrates my understanding
- **Publish** it, so it becomes part of my portfolio

Write-ups live on my Substack, [CyberwithP](https://cyberwithprudie.substack.com). Everything I build lives here.

## Progress

| Day | Topic | Build | Write-up |
|-----|-------|-------|----------|
| 01 | AI architecture fundamentals | [Architecture + trust-boundary diagram](day-01-architecture/) | [Day 1: Documenting my AI Security Journey](https://cyberwithprudie.substack.com/p/day-1-documenting-my-ai-security) |
| 02 | Prompt injection | Coming soon | |
| 03 | Sensitive information disclosure | [leakcheck: context-window leak scanner](day-03-sensitive-info/) | [Day 3: What AI Systems Leak](https://cyberwithprudie.substack.com/p/day-3-what-ai-systems-leak-sensitive) |
| 04 | Excessive agency | [agencycheck: agent permission audit + tool-call gate](day-04-excessive-agency/) | [Day 4: When Your AI Agent Does Too Much](https://cyberwithprudie.substack.com/p/day-4-when-your-ai-agent-does-too) |

## Repo layout

```
day-01-architecture/
  README.md     the Day 1 write-up
  diagram.png   architecture diagram with 6 trust boundaries
day-03-sensitive-info/
  README.md      leakcheck docs
  leakcheck.py   pre-flight scanner for secrets, PII and cross-tenant docs
  samples/       a leaky request and the same request after the fixes
  tests/         unit tests (run in CI)
day-04-excessive-agency/
  README.md       agencycheck docs
  agencycheck.py  audits an agent's tools for excessive agency, and gates its tool calls at runtime
  samples/        an over-privileged agent, the least-privilege fix, and a prompt-injected session
  tests/          unit tests (run in CI)
```

## Disclaimer

Everything here is for learning. Any testing is done only on systems I own or am explicitly allowed to test.

## License

Code in this repo is released under the [MIT License](LICENSE).
