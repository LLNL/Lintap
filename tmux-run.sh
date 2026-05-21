#!/bin/bash

# Run both the Lintap sensor and the OS performance data collector (pidstat-collect) in parallel, in foreground sessions.

WINTAP_HOME="${WINTAP_HOME:-$HOME/git/wintap/wintap}"
WINTAP_DATA_ROOT="${WINTAP_DATA_ROOT:-/home/ubuntu/data/debug}"
PIDSTAT_OUTPUT_PATH="${PIDSTAT_OUTPUT_PATH:-$WINTAP_DATA_ROOT/pidstat}"

# Name of the tmux session
SESSION="${SESSION:-lintap_dev}"

# Kill existing session if it exists
tmux kill-session -t $SESSION 2>/dev/null

# Create a new session (detached)
tmux new-session -d -s $SESSION

# Split the window into two panes
tmux split-window -v -t $SESSION

# Pane 1: Run the .NET project. Preserve WINTAP_DATA_ROOT through sudo.
tmux send-keys -t "$SESSION:0.0" "sudo WINTAP_DATA_ROOT='$WINTAP_DATA_ROOT' dotnet run --project '$WINTAP_HOME/Lintap.csproj'" C-m

# Pane 2: Run the collector into the same run root.
tmux send-keys -t "$SESSION:0.1" "./pidstat-collect.sh '$PIDSTAT_OUTPUT_PATH'" C-m

# Attach to the session
tmux attach-session -t $SESSION
