# Farmhouse Networking build notes

This fork of [gbrigandi/mcp-server-wazuh](https://github.com/gbrigandi/mcp-server-wazuh) carries Farmhouse Networking's alert-handling changes. The upstream README.md is unchanged and still describes the server and all of its tools.

No credentials, hostnames or environment files live in this repo. Deployment settings are kept in a separate private launcher repo and an encrypted local secret store. `.env` is git-ignored.

## Branches

| Branch | Contents |
|---|---|
| `farmhouse-extended-alerts` | Upstream plus Farmhouse changes. **Build this one.** |
| `main` | Kept identical to upstream `main` |
| `pre-rmcp` | Kept identical to upstream `pre-rmcp` |

## Farmhouse changes (src/tools/alerts.rs, Cargo.toml)

- Server-side alert filtering, so the client doesn't pull every alert and filter it locally
- `search_after` pagination for large alert sets
- Raw JSON output option

## Build (Windows)

```powershell
# needs Rust: https://rustup.rs
git clone https://github.com/FarmhouseNetworking/mcp-server-wazuh.git wazuh-src
cd wazuh-src
git checkout farmhouse-extended-alerts
cargo build --release
# output: target\release\mcp-server-wazuh.exe
```

Copy the binary into the launcher folder (keeping the old one as a dated `.bak`), then restart Claude Desktop.

## Pulling upstream updates

```powershell
git remote add upstream https://github.com/gbrigandi/mcp-server-wazuh.git   # once
git fetch upstream
git checkout main; git merge --ff-only upstream/main; git push origin main
git checkout farmhouse-extended-alerts; git merge main
cargo build --release   # test before pushing
git push origin farmhouse-extended-alerts
```

(GitHub's **Sync fork** button on `main` does the first half of this.)

## License

Upstream is MIT licensed (see LICENSE). Keep the LICENSE file.