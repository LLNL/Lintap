#!/bin/bash

# Run both the Lintap sensor and the OS performance data collector (pidstat-collect) in parallel, in foreground sessions.

WINTAP_HOME="~/git/wintap/wintap"

# Name of the tmux session
SESSION="lintap_dev"

# Kill existing session if it exists
tmux kill-session -t $SESSION 2>/dev/null

# Create a new session (detached)
tmux new-session -d -s $SESSION

# Split the window into two panes
tmux split-window -v -t $SESSION

# Pane 1: Run the .NET project (sudo required, from the other projects dir)
tmux send-keys -t $SESSION:0.0 "sudo WINTAP_DATA_ROOT=/home/ubuntu/data/debug dotnet run --project $WINTAP_HOME/Lintap.csproj" C-m

# Pane 2: Run the collector
tmux send-keys -t $SESSION:0.1 "./pidstat-collect.sh" C-m

# Attach to the session
tmux attach-session -t $SESSION
