import marimo as mo

__generated_with = "0.13.15"
app = mo.App(width="full")


@app.cell
def _():
    import os
    from pathlib import Path

    import duckdb
    import marimo as mo
    import pandas as pd
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots

    def candidate_database_paths() -> list[Path]:
        """Return database candidates in preferred order.

        Supports both the newer DBT database location and the older TeleTap sample DB.
        """
        candidates: list[Path] = []

        for env_name in ("TELETAP_DATABASE", "WINTAP_TELETAP_DATABASE", "WINTAP_DBT_DATABASE"):
            value = os.getenv(env_name)
            if value:
                candidates.append(Path(value).expanduser())

        data_root = os.getenv("WINTAP_DATA_ROOT")
        if data_root:
            root = Path(data_root).expanduser()
            candidates.extend(
                [
                    root / "duckdb" / "wintap.duckdb",
                    root / "duckdb" / "teletap.duckdb",
                    root / "teletap.duckdb",
                    root / "sample.db",
                ]
            )

        candidates.append(Path("sample.db"))

        # Deduplicate while preserving order.
        unique: list[Path] = []
        seen: set[str] = set()
        for candidate in candidates:
            key = str(candidate)
            if key not in seen:
                seen.add(key)
                unique.append(candidate)
        return unique

    def default_database_path() -> Path:
        for candidate in candidate_database_paths():
            if candidate.exists():
                return candidate
        return candidate_database_paths()[0]

    def query_df(con: duckdb.DuckDBPyConnection, sql: str) -> pd.DataFrame:
        try:
            return con.execute(sql).df()
        except Exception as exc:
            return pd.DataFrame({"error": [str(exc)], "sql": [sql]})

    def table_exists(con: duckdb.DuckDBPyConnection, table_name: str) -> bool:
        return bool(
            con.execute(
                """
                select count(*)
                from information_schema.tables
                where table_schema = 'main'
                  and lower(table_name) = lower(?)
                """,
                [table_name],
            ).fetchone()[0]
        )

    return (
        Path,
        candidate_database_paths,
        default_database_path,
        duckdb,
        go,
        make_subplots,
        mo,
        query_df,
        table_exists,
    )


@app.cell
def _(mo):
    mo.md(
        """
        # TeleTap Metrics – Coordinated Zoom

        Marimo version of `grokdata.py`. It reads the first available DuckDB database from:

        1. `TELETAP_DATABASE`
        2. `WINTAP_TELETAP_DATABASE`
        3. `WINTAP_DBT_DATABASE`
        4. `$WINTAP_DATA_ROOT/duckdb/wintap.duckdb`
        5. `$WINTAP_DATA_ROOT/duckdb/teletap.duckdb`
        6. `$WINTAP_DATA_ROOT/teletap.duckdb`
        7. `$WINTAP_DATA_ROOT/sample.db`
        8. `./sample.db`

        It expects the DB to contain the TeleTap/DBT chart views: `perf_chart`, `process_chart`, `file_chart`, and `network_chart`.
        """
    )
    return


@app.cell
def _(candidate_database_paths, default_database_path, mo):
    selected_db = mo.ui.text(
        value=str(default_database_path()),
        label="DuckDB database path",
        full_width=True,
    )
    candidate_table = mo.ui.table(
        [{"candidate": str(path), "exists": path.exists()} for path in candidate_database_paths()],
        pagination=False,
    )
    mo.vstack([selected_db, mo.md("### Candidate database paths"), candidate_table])
    return (selected_db,)


@app.cell
def _(Path, duckdb, mo, selected_db):
    database_path = Path(selected_db.value).expanduser()
    if not database_path.exists():
        mo.stop(True, mo.md(f"Database not found: `{database_path}`"))
    con = duckdb.connect(str(database_path), read_only=True)
    return con, database_path


@app.cell
def _(con, database_path, mo, table_exists):
    required_views = ["perf_chart", "process_chart", "file_chart", "network_chart"]
    view_status = [{"view": view, "exists": table_exists(con, view)} for view in required_views]
    missing = [row["view"] for row in view_status if not row["exists"]]
    mo.vstack(
        [
            mo.md(f"**Connected database:** `{database_path}`"),
            mo.ui.table(view_status, pagination=False),
        ]
    )
    if missing:
        mo.stop(
            True,
            mo.md(
                "Missing required chart views: "
                + ", ".join(f"`{view}`" for view in missing)
                + ". Run the TeleTap SQL pipeline or `make dbt-build` first."
            ),
        )
    return


@app.cell
def _(con, query_df):
    df = query_df(
        con,
        """
        select
            pf.*,
            p.num_rows as procs,
            f.num_rows as file,
            n.num_rows as net
        from perf_chart pf
        left outer join process_chart p on pf.time_chunk = p.time_chunk
        left outer join file_chart f on pf.time_chunk = f.time_chunk
        left outer join network_chart n on pf.time_chunk = n.time_chunk
        order by pf.time_chunk
        """,
    )
    if "time_chunk" in df.columns:
        df["time_chunk"] = df["time_chunk"].astype("datetime64[ns]")
    return (df,)


@app.cell
def _(df, mo):
    labels = {
        "uniq_process_name": "Unique Processes",
        "max_cpu": "Max CPU %",
        "max_mem": "Max Memory %",
        "max_read": "Max Disk Read (KB/s)",
        "max_write": "Max Disk Write (KB/s)",
        "num_rows": "Pidstat Samples",
        "procs": "New Processes Started",
        "file": "New File Events",
        "net": "New Network Flows",
    }

    colors = {
        "uniq_process_name": "steelblue",
        "max_cpu": "red",
        "max_write": "orange",
        "procs": "darkblue",
        "file": "purple",
        "net": "green",
        "max_mem": "gray",
        "max_read": "brown",
        "num_rows": "teal",
    }

    available_metrics = [column for column in labels if column in df.columns]
    default_metrics = [
        metric
        for metric in ["uniq_process_name", "max_cpu", "max_write", "procs", "file", "net"]
        if metric in available_metrics
    ]
    selected_metrics = mo.ui.multiselect(
        options=available_metrics,
        value=default_metrics,
        label="Select metrics — zoom/pan one subplot and the shared x-axis follows",
    )
    selected_metrics
    return colors, labels, selected_metrics


@app.cell
def _(colors, df, go, labels, make_subplots, mo, selected_metrics):
    if df.empty or "error" in df.columns:
        mo.ui.table(df, pagination=False)
    elif not selected_metrics.value:
        mo.md("Select at least one metric.")
    else:
        fig = make_subplots(
            rows=len(selected_metrics.value),
            cols=1,
            shared_xaxes=True,
            vertical_spacing=0.04,
        )

        for row_num, column in enumerate(selected_metrics.value, 1):
            y_values = df[column].fillna(0)
            if column in ["procs", "file", "net"]:
                trace = go.Bar(
                    x=df["time_chunk"],
                    y=y_values,
                    name=labels[column],
                    marker_color=colors[column],
                )
            else:
                trace = go.Scatter(
                    x=df["time_chunk"],
                    y=y_values,
                    mode="lines",
                    name=labels[column],
                    line_color=colors[column],
                )

            fig.add_trace(trace, row=row_num, col=1)
            fig.update_yaxes(title_text=labels[column], row=row_num, col=1)

        fig.update_layout(
            height=max(320, 260 * len(selected_metrics.value)),
            margin=dict(l=60, r=20, t=40, b=20),
            hovermode="x unified",
            showlegend=False,
        )
        fig.update_xaxes(rangeslider_visible=False)
        fig
    return


@app.cell
def _(df, mo):
    if df.empty or "error" in df.columns:
        summary = df
    else:
        summary = df.describe(include="all").transpose().reset_index(names="metric")
    mo.vstack([mo.md("## Raw joined chart data"), mo.ui.table(df, page_size=25), mo.md("## Metric summary"), mo.ui.table(summary, page_size=25)])
    return


if __name__ == "__main__":
    app.run()
