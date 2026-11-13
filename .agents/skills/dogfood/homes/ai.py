"""A heavy user of AI coding tools: session records of several agents, MCP
server configs, the tools' own sign-ins, and a shell history with pasted keys."""

import json

from .lib import DEBATABLE, HIDDEN, STORED, WORTH

CLAUDE_PROJECTS = [
    "-Users-dev-code-agent-app", "-Users-dev-code-rag-demo", "-Users-dev-code-evals", "-Users-dev-code-prompt-lib",
    "-Users-dev-code-scanner-rules", "-Users-dev-code-infra", "-Users-dev-code-web", "-Users-dev-notes",
]


def record(command, output):
    """One tool call and its result, as an agent's session record keeps them."""
    return (
        json.dumps({"type": "assistant", "message": {"content": [
            {"type": "tool_use", "name": "Bash", "input": {"command": command}}]}})
        + "\n"
        + json.dumps({"type": "user", "message": {"content": [{"type": "tool_result", "content": output}]}})
        + "\n"
    )


def session(h, lines, *planted):
    """A session record of ordinary work, with `planted` records in its middle."""
    filler = [record(f"sed -n 1,40p src/{h.chars(8)}.ts", h.source(6)) for _ in range(lines)]
    middle = len(filler) // 2
    return "".join(filler[:middle]) + "".join(planted) + "".join(filler[middle:])


def build(h):
    keys = {name: h.token(kind) for name, kind in (
        ("github", "github"), ("anthropic", "anthropic"), ("openai", "openai"), ("huggingface", "huggingface"))}
    claude_code(h, keys)
    other_agents(h, keys)
    mcp_configs(h, keys)
    projects(h, keys)
    shell(h, keys)
    bulk(h)


def claude_code(h, keys):
    base = ".claude/projects"
    for project in CLAUDE_PROJECTS:
        for _ in range(22):
            h.put(f"{base}/{project}/{h.chars(8, '0123456789abcdef')}-{h.chars(4, '0123456789abcdef')}.jsonl",
                  session(h, h.rng.randint(40, 400)))

    curl = record(f"curl -s -H 'Authorization: Bearer {keys['github']}' https://api.github.example.invalid/user", "{}")
    for n in range(6):
        h.plant(f"{base}/-Users-dev-code-agent-app/gh-{n}.jsonl", session(h, 120, curl),
                "GitHub token used in a command, recorded in a session", WORTH,
                "a real token in a session record; one item for all six records would be right", group="github")
    h.plant(f"{base}/-Users-dev-code-agent-app/gh-0/subagents/agent-a1.jsonl", session(h, 30, curl),
            "the same token in a subagent's record", WORTH, "the same token again", group="github")

    cat = record("cat .env", f"ANTHROPIC_API_KEY={keys['anthropic']}\nLOG_LEVEL=debug\n")
    for n in range(2):
        h.plant(f"{base}/-Users-dev-code-agent-app/env-{n}.jsonl", session(h, 200, cat),
                "Anthropic key printed by 'cat .env', recorded in a session", WORTH,
                "a real key in a session record", group="anthropic")
    h.plant(f"{base}/-Users-dev-code-infra/aws-0.jsonl",
            session(h, 150, record("env | grep AWS", f"AWS_ACCESS_KEY_ID={h.token('aws-id')}\nAWS_SECRET_ACCESS_KEY={h.chars(40)}\n")),
            "AWS keys printed by 'env', recorded in a session", WORTH, "real keys in a session record")
    h.plant(f"{base}/-Users-dev-code-web/hook-0.jsonl",
            session(h, 90, record("grep -r hooks.slack src/", f"src/notify.ts: const url = '{h.token('slack-hook')}'\n")),
            "Slack webhook URL printed by grep, recorded in a session", WORTH, "anyone with the URL can post")

    fixture = "".join(f'  "case{n}": "{h.token("github")}",\n' for n in range(8))
    h.plant(f"{base}/-Users-dev-code-scanner-rules/fixtures-0.jsonl",
            session(h, 100, record("cat tests/fixtures/tokens.json", "{\n" + fixture + "}\n")),
            "eight token-shaped test strings an agent read from a fixture file", DEBATABLE,
            "made-up test data, but shaped like real tokens")
    h.plant(f"{base}/-Users-dev-notes/docs-0.jsonl",
            session(h, 60, record("curl -s https://docs.github.example.invalid/rest",
                                  "Example: Authorization: Bearer gh" + "p_16C7e42F292c6912E7" + "710c838347Ae178B4a\n")),
            "the example token from GitHub's documentation, in a fetched page", HIDDEN,
            "a published example, not a credential")
    h.plant(f"{base}/-Users-dev-notes/cut-0.jsonl",
            session(h, 60, record("claude config list", "apiKey: sk-" + "ant-api03-AbCd...wXyZ\n")),
            "a key shown shortened by the tool that printed it", HIDDEN, "the shortened text is not the key")

    kept_beside_transcripts(h, keys)


def kept_beside_transcripts(h, keys):
    """What Claude Code keeps besides transcripts: backups of edited files,
    shell snapshots, the prompt history, its sign-in and its settings."""
    h.plant(".claude/file-history/5f2c1a/9e8d7c@v1", f"ANTHROPIC_API_KEY={keys['anthropic']}\nLOG_LEVEL=debug\n",
            "the agent's backup of a .env file it edited", WORTH, "the same key in a backup copy", group="anthropic")
    for n in range(14):
        h.plant(f".claude/shell-snapshots/snapshot-zsh-179000{n:04}-{h.chars(6)}.sh",
                f"# Snapshot file\nexport PATH=/usr/bin:/bin\nexport HF_TOKEN={keys['huggingface']}\nexport EDITOR=vim\n",
                "shell snapshot that repeats a token exported in .zshrc", WORTH,
                "the same token, copied at every session start", group="huggingface")
    h.plant(".claude/history.jsonl",
            json.dumps({"display": "use this key for the eval run: " + keys["openai"], "project": "/Users/dev/code/evals"}) + "\n"
            + "".join(json.dumps({"display": f"fix the {h.chars(6)} test"}) + "\n" for _ in range(300)),
            "OpenAI key pasted into a prompt", WORTH, "a real key in the prompt history", group="openai")
    h.json(".claude/.credentials.json",
           {"claudeAiOauth": {"accessToken": "sk-" + "ant-oat01-" + h.chars(90), "refreshToken": "sk-" + "ant-ort01-" + h.chars(90),
                              "expiresAt": 1790000000000}}, mode=0o600)
    h.expect(".claude/.credentials.json", "Claude Code's stored sign-in", STORED, "kept by the tool for itself")
    h.json(".claude/settings.json",
           {"env": {"CLAUDE_CODE_USE_BEDROCK": "1", "AWS_BEARER_TOKEN_BEDROCK": h.token("bedrock")},
            "apiKeyHelper": "~/bin/get-key.sh", "permissions": {"allow": ["Bash(npm test)"]}})
    h.expect(".claude/settings.json", "Bedrock API key in Claude Code's settings", WORTH, "a real key in plain text")
    h.tree(".claude/todos", 200, (".json",), 1, 3)
    h.tree(".claude/plugins/marketplaces/official/plugins", 400, (".md", ".json"), 3, 6)


def other_agents(h, keys):
    rollout = session(h, 150, record("curl https://api.openai.example.invalid/v1/models -H 'Authorization: Bearer "
                                     + keys["openai"] + "'", "{}"))
    for day in range(1, 31):
        h.put(f".codex/sessions/2026/11/{day:02}/rollout-2026-11-{day:02}T09-00-00-{h.chars(8)}.jsonl", session(h, 120))
    h.plant(".codex/sessions/2026/11/03/rollout-2026-11-03T10-00-00-key.jsonl", rollout,
            "OpenAI key used in a command, recorded by Codex", WORTH, "a real key in a session record", group="openai")
    h.plant(".codex/log/codex-tui.log", "INFO starting\n" * 400 + f"DEBUG env GITHUB_TOKEN={keys['github']}\n" + "INFO done\n" * 400,
            "GitHub token in Codex's debug log", WORTH, "the same token in a log", group="github")
    h.plant(".codex/config.toml",
            'model = "gpt-5"\n\n[mcp_servers.tracker]\nurl = "https://mcp.tracker.example.invalid/mcp"\n'
            f'http_headers = {{ "Authorization" = "Bearer {h.token("linear")}" }}\n\n'
            '[mcp_servers.docs]\nurl = "https://mcp.docs.example.invalid/mcp"\nbearer_token_env_var = "DOCS_TOKEN"\n',
            "Linear key in a Codex MCP server's headers", WORTH, "a real key in plain text")
    h.expect(".codex/config.toml", "Codex MCP server that names an environment variable", HIDDEN, "a reference, not a value")
    h.plant(".cursor/projects/Users-dev-code-web/agent-transcripts/t-1.txt",
            session(h, 80, record("npx vercel env pull", f"DIGITALOCEAN_TOKEN={h.token('digitalocean')}\n")),
            "DigitalOcean token in a Cursor agent transcript", WORTH, "a real token in a session record")
    h.plant("Library/Application Support/Cursor/User/globalStorage/state.vscdb",
            b"SQLite format 3\x00" + h.rng.randbytes(900_000)
            + f'{{"text":"my key is {h.token("stripe")}"}}'.encode() + h.rng.randbytes(50_000),
            "Stripe key typed into Cursor's chat, kept in its database", WORTH, "a real key in the chat history")
    h.json("Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/tasks/1790000001/api_conversation_history.json",
           [{"role": "user", "content": "deploy with token " + h.token("gitlab")}])
    h.expect("Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/tasks/1790000001/api_conversation_history.json",
             "GitLab token in a Cline task's conversation", WORTH, "a real token in a session record")
    h.plant("Library/Logs/Claude/mcp-server-github.log",
            "[info] starting server\n" * 50 + f"[debug] env GITHUB_PERSONAL_ACCESS_TOKEN={keys['github']}\n",
            "GitHub token in Claude Desktop's MCP server log", WORTH, "the same token in a log", group="github")
    h.json(".gemini/oauth_creds.json", {"access_token": "ya29." + h.chars(180), "refresh_token": "1//" + h.chars(60),
                                        "token_type": "Bearer"}, mode=0o600)
    h.expect(".gemini/oauth_creds.json", "Gemini CLI's stored sign-in", STORED, "kept by the tool for itself")
    h.plant(".gemini/.env", f"GEMINI_API_KEY={h.token('google')}\n", "Gemini API key in the CLI's .env", WORTH, "a real key")
    h.json(".config/github-copilot/apps.json", {"github.com:Iv1.b507a08c87ecfe98": {"user": "dev", "oauth_token": "gh" + "u_" + h.chars(36)}}, mode=0o600)
    h.expect(".config/github-copilot/apps.json", "GitHub Copilot's stored sign-in", STORED, "kept by the tool for itself")
    for n in range(3):
        name = h.chars(32, "0123456789abcdef")
        h.json(f".mcp-auth/mcp-remote-0.1.18/{name}_tokens.json",
               {"access_token": h.chars(64), "token_type": "Bearer", "refresh_token": h.chars(64), "expires_in": 3600}, mode=0o600)
        h.expect(f".mcp-auth/mcp-remote-0.1.18/{name}_tokens.json", "OAuth sign-in mcp-remote keeps for an MCP server",
                 STORED, "kept by the tool for itself")
        h.json(f".mcp-auth/mcp-remote-0.1.18/{name}_client_info.json", {"client_id": h.chars(24), "redirect_uris": ["http://localhost:3334"]})
    h.plant(".continue/config.yaml",
            f"models:\n  - name: sonnet\n    provider: anthropic\n    apiKey: {keys['anthropic']}\n",
            "Anthropic key in Continue's config", WORTH, "the same key in a config", group="anthropic")


def mcp_configs(h, keys):
    h.json(".claude.json", {
        "numStartups": 412, "oauthAccount": {"emailAddress": "dev@example.invalid"},
        "mcpServers": {
            "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                       "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": keys["github"]}},
            "search": {"command": "npx", "args": ["-y", "search-mcp"], "env": {"BRAVE_API_KEY": "BSA" + h.chars(28)}},
            "postgres": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres",
                                                    f"postgresql://readonly:{h.password()}@db.example.invalid/app"]},
            "notion": {"command": "npx", "args": ["-y", "notion-mcp"], "env": {"NOTION_TOKEN": "${NOTION_TOKEN}"}}},
        "projects": {f"/Users/dev/code/{n}": {"history": [{"display": h.source(1)} for _ in range(40)]} for n in ("web", "infra")}})
    h.expect(".claude.json", "GitHub token in an MCP server's environment", WORTH, "the same token in a config", group="github")
    h.expect(".claude.json", "search API key in an MCP server's environment", WORTH, "a real key in plain text")
    h.expect(".claude.json", "database password in an MCP server's arguments", WORTH, "a real password in plain text")
    h.expect(".claude.json", "MCP server that names an environment variable", HIDDEN, "a reference, not a value")
    h.json(".cursor/mcp.json", {"mcpServers": {
        "linear": {"command": "npx", "args": ["-y", "linear-mcp"], "env": {"LINEAR_API_KEY": h.token("linear")}},
        "sentry": {"url": "https://mcp.sentry.example.invalid", "headers": {"Authorization": "Bearer ${env:SENTRY_TOKEN}"}}}})
    h.expect(".cursor/mcp.json", "Linear key in a Cursor MCP server's environment", WORTH, "a real key in plain text")
    h.expect(".cursor/mcp.json", "Cursor MCP server that names an environment variable", HIDDEN, "a reference, not a value")
    h.json(".codeium/windsurf/mcp_config.json", {"mcpServers": {"stripe": {"command": "npx", "args": [
        "-y", "@stripe/mcp", "--api-key=" + h.token("stripe")]}}})
    h.expect(".codeium/windsurf/mcp_config.json", "Stripe key in an MCP server's arguments", WORTH, "a real key in plain text")
    h.json("Library/Application Support/Code/User/mcp.json", {
        "inputs": [{"id": "gh", "type": "promptString", "password": True}],
        "servers": {"github": {"url": "https://api.githubcopilot.example.invalid/mcp", "headers": {"Authorization": "Bearer ${input:gh}"}}}})
    h.expect("Library/Application Support/Code/User/mcp.json", "VS Code MCP server that asks for its token", HIDDEN,
             "a reference, not a value")


def projects(h, keys):
    for name in ("agent-app", "rag-demo", "evals", "prompt-lib", "web"):
        h.repo(f"code/{name}", f"git@github.com:dev/{name}.git")
        h.tree(f"code/{name}/src", 150, (".py", ".ts"), 3)
    h.plant("code/agent-app/.env", f"ANTHROPIC_API_KEY={keys['anthropic']}\nLOG_LEVEL=debug\n",
            "Anthropic key in a project's .env", WORTH, "a real key", group="anthropic")
    h.json("code/agent-app/.mcp.json", {"mcpServers": {"tracker": {"command": "npx", "args": ["-y", "tracker-mcp"],
                                                                 "env": {"TRACKER_API_TOKEN": h.chars(40)}}}})
    h.expect("code/agent-app/.mcp.json", "API token in a project's MCP config", WORTH, "a real token in plain text")
    h.plant("code/agent-app/.aider.chat.history.md",
            "# aider chat started\n\n" + "#### refactor the client\n\nDone.\n\n" * 200
            + f"#### set OPENAI_API_KEY to {keys['openai']}\n\nOk.\n",
            "OpenAI key in Aider's chat history", WORTH, "the same key in a chat history", group="openai")
    h.plant("code/rag-demo/.env",
            f"PINECONE_API_KEY={h.token('pinecone')}\nCOHERE_API_KEY={h.chars(40)}\nLANGSMITH_API_KEY={h.token('langsmith')}\n",
            "Pinecone API key", WORTH, "a real key")
    h.expect("code/rag-demo/.env", "Cohere API key", WORTH, "a real key")
    h.expect("code/rag-demo/.env", "LangSmith API key", WORTH, "a real key")
    h.json("code/rag-demo/.claude/settings.local.json", {"permissions": {"allow": [
        "Bash(npm test)", f"Bash(curl -H 'x-api-key: {keys['anthropic']}' https://api.anthropic.example.invalid/v1/models)"]}})
    h.expect("code/rag-demo/.claude/settings.local.json", "Anthropic key inside an allowed command", WORTH,
             "the same key in a settings file", group="anthropic")
    cells = [{"cell_type": "code", "source": [h.source(3)], "outputs": []} for _ in range(40)]
    cells.append({"cell_type": "code", "source": ["import os; print(os.environ)"],
                  "outputs": [{"text": [f"'COHERE_KEY': '{h.chars(40)}', 'HF_TOKEN': '{keys['huggingface']}'"]}]})
    h.json("code/evals/notebooks/explore.ipynb", {"cells": cells, "nbformat": 4})
    h.expect("code/evals/notebooks/explore.ipynb", "Hugging Face token printed in a notebook's output", WORTH,
             "the same token in a notebook", group="huggingface")
    h.plant(".cache/huggingface/token", keys["huggingface"] + "\n", "Hugging Face CLI's token file", WORTH,
            "the same token in the CLI's file", group="huggingface")


def shell(h, keys):
    h.plant(".zshrc", f"export HF_TOKEN={keys['huggingface']}\nexport EDITOR=vim\n",
            "Hugging Face token exported from .zshrc", WORTH, "a real token in a startup file", group="huggingface")
    h.plant(".zsh_history",
            f": 1790000000:0;export ANTHROPIC_API_KEY={keys['anthropic']}\n"
            f": 1790000100:0;claude mcp add github -e GITHUB_PERSONAL_ACCESS_TOKEN={keys['github']} -- npx -y server-github\n"
            f": 1790000200:0;GEMINI_API_KEY={h.token('google')} gemini -p hello\n"
            f": 1790000300:0;mcp-proxy --api-key {h.chars(32)} --port 8080\n"
            ": 1790000400:0;claude --resume\n: 1790000500:0;codex exec 'run the tests'\n",
            "Anthropic key exported in the shell", WORTH, "the same key typed into the shell", group="anthropic", mode=0o600)
    h.expect(".zsh_history", "GitHub token given to 'claude mcp add'", WORTH, "the same token typed into the shell", group="github")
    h.expect(".zsh_history", "Gemini key given to one command", WORTH, "a real key typed into the shell")
    h.expect(".zsh_history", "API key given to '--api-key'", WORTH, "a real key typed into the shell")


def bulk(h):
    h.tree(".cursor/extensions/ms-python.python-2026.2.0/out", 1500, (".js",), 4)
    h.tree(".vscode/extensions/github.copilot-1.250.0/dist", 1200, (".js",), 3)
    h.tree("Library/Application Support/Cursor/CachedData", 1500, (".code",), 2, 4)
    h.tree("Library/Application Support/Claude/Cache", 800, (".bin",), 2, 4)
    h.tree("Library/Application Support/Code/User/workspaceStorage", 900, (".json",), 2, 5)
    h.node_modules("code/agent-app", 500)
    h.node_modules("code/web", 800)
    h.tree("code/evals/.venv/lib/python3.12/site-packages", 2500, (".py",), 4)
    h.tree(".ollama/models/manifests", 60, ("",), 4, 3)
