# Install GRASP in Claude Desktop

Claude Desktop runs local (stdio) MCP servers configured in
`claude_desktop_config.json`.

## 1. Put `grasp-mcp` on PATH

```bash
pipx install "git+https://github.com/CodeTonight-SA/grasp"
```

## 2. Edit the config

Open **Settings → Developer → Edit Config** (this creates the file if it does
not exist), or edit it directly:

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows (standard `.exe` installer) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Windows (Microsoft Store / WinGet / MSIX installer) | `C:\Users\YourName\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json` |
| Linux | `~/.config/claude-desktop/claude_desktop_config.json` |

Add the server under `mcpServers`:

```json
{
  "mcpServers": {
    "grasp": {
      "command": "grasp-mcp"
    }
  }
}
```

If Desktop cannot find the command (it launches servers with a limited PATH),
use the absolute path to the binary instead — `command -v grasp-mcp` on
macOS/Linux prints it. On Windows, backslashes in JSON must be escaped
(`"C:\\Users\\..."`).

## 3. Restart

Config changes require a **full app restart**. After restarting, the grasp
tools appear in the tools menu.

Troubleshooting logs: macOS `~/Library/Logs/Claude`, Windows
`%APPDATA%\Claude\Logs`.

Note: Anthropic's 2026 direction for one-click installs is Desktop Extensions
(`.mcpb` packages, **Settings → Extensions**). GRASP does not ship an `.mcpb`
yet; the JSON entry above is the supported path today.
