# app.py  ←  The One That Just Works™ (2025–2030 edition)
import streamlit as st
import duckdb
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots

st.set_page_config(page_title="TeleTap Metrics Coordinated Zoom", layout="wide")
st.title("TeleTap Metrics – Coordinated Zoom")

# Load data
con = duckdb.connect("sample.db", read_only=True)
df = con.execute("""
select pf.*, procs:p.num_rows, file:f.num_rows, net:n.num_rows
from perf_chart pf
left outer join process_chart p on pf.time_chunk=p.time_chunk
left outer join file_chart f on pf.time_chunk=f.time_chunk
left outer join network_chart n on pf.time_chunk=n.time_chunk
order by all""").df()
con.close()

df['time_chunk'] = pd.to_datetime(df['time_chunk'])

# Shared zoom state
if 'zoom' not in st.session_state:
    st.session_state.zoom = None

# Labels & colors
labels = {
    "uniq_process_name": "Unique Processes",
    "max_cpu":          "Max CPU %",
    "max_mem":          "Max Memory (GB)",
    "max_read":         "Max Disk Read (KB/10s)",
    "max_write":        "Max Disk Write (KB/10s)",
    "num_rows":         "Process Samples",
    "procs":            "New Processes Started",
    "file":             "New File Events",
    "net":              "New Network Flows",
}

colors = {
    "uniq_process_name": "steelblue",
    "max_cpu":          "red",
    "max_write":        "orange",
    "procs":            "darkblue",
    "file":             "purple",
    "net":              "green",
    "max_mem":          "gray",
    "max_read":         "brown",
    "num_rows":         "teal",
}

selected = st.multiselect(
    "Select metrics — zoom any chart → all follow",
    options=list(labels.keys()),
    default=["uniq_process_name", "max_cpu", "max_write", "procs", "file", "net"],
    format_func=labels.get
)

if not selected:
    st.stop()

fig = make_subplots(rows=len(selected), cols=1, shared_xaxes=True, vertical_spacing=0.04)

for i, col in enumerate(selected, 1):
    if col in ["procs", "file", "net"]:
        trace = go.Bar(x=df['time_chunk'], y=df[col], name=labels[col],
                       marker_color=colors[col])
    else:
        trace = go.Scatter(x=df['time_chunk'], y=df[col], mode='lines',
                          name=labels[col], line_color=colors[col])
    fig.add_trace(trace, row=i, col=1)
    fig.update_yaxes(title_text=labels[col], row=i, col=1)

# Apply saved zoom
if st.session_state.zoom:
    fig.update_xaxes(range=st.session_state.zoom)

# Modern, warning-free callback
def on_zoom(trace, points, selector):
    if selector and getattr(selector, "xaxis", None) and selector.xaxis.range:
        st.session_state.zoom = selector.xaxis.range
    else:  # double-click or reset
        st.session_state.zoom = None
    st.rerun()

for trace in fig.data:
    trace.on_selection(on_zoom)

fig.update_layout(height=300 * len(selected), margin=dict(l=60, r=20, t=40, b=20))

# Future-proof width parameter
st.plotly_chart(fig, use_container_width=True, width='stretch', config={'scrollZoom': True})

st.caption("Zoom/pan any chart → all charts instantly sync · Double-click to reset")