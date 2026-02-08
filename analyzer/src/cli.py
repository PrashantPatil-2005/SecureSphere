"""
=============================================================================
SecuriSphere - Analyzer CLI Interface
=============================================================================

Command-line interface for the anomaly detection system.

Commands:
- baseline: Build network traffic baseline from Zeek logs
- detect:   Run anomaly detection against current logs
- watch:    Continuously monitor logs for anomalies
- report:   Generate anomaly report

=============================================================================
"""

import click
import json
import time
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging

from .zeek_parser import ZeekLogParser
from .baseline import BaselineBuilder
from .detector import AnomalyDetector, Anomaly, Severity

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rich console for pretty output
console = Console()


class LogFileHandler(FileSystemEventHandler):
    """Handler for watching Zeek log file changes."""
    
    def __init__(self, detector: AnomalyDetector, callback):
        self.detector = detector
        self.callback = callback
        self.last_check = datetime.now()
    
    def on_modified(self, event):
        if event.src_path.endswith('.log'):
            self.callback(event.src_path)


@click.group()
@click.option('--log-dir', '-l', default='/logs', help='Zeek log directory')
@click.option('--output-dir', '-o', default='/analyzer/output', help='Output directory')
@click.pass_context
def cli(ctx, log_dir, output_dir):
    """
    SecuriSphere Analyzer - Network Anomaly Detection
    
    Analyzes Zeek network logs to detect security anomalies.
    """
    ctx.ensure_object(dict)
    ctx.obj['log_dir'] = log_dir
    ctx.obj['output_dir'] = output_dir
    
    # Create output directory if needed
    Path(output_dir).mkdir(parents=True, exist_ok=True)


@cli.command()
@click.option('--output', '-o', default='baseline.json', help='Baseline output file')
@click.pass_context
def baseline(ctx, output):
    """
    Build network traffic baseline from Zeek logs.
    
    Analyzes historical log data to establish normal behavior patterns.
    """
    log_dir = ctx.obj['log_dir']
    output_dir = ctx.obj['output_dir']
    output_path = Path(output_dir) / output
    
    console.print(Panel(
        f"[bold blue]Building Network Baseline[/bold blue]\n"
        f"Log directory: {log_dir}\n"
        f"Output: {output_path}",
        title="SecuriSphere Analyzer"
    ))
    
    with console.status("[bold green]Analyzing logs..."):
        builder = BaselineBuilder(log_dir)
        baseline_data = builder.build_full_baseline()
        builder.save_baseline(baseline_data, str(output_path))
    
    # Display baseline summary
    table = Table(title="Baseline Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    conn = baseline_data.get('connection', {})
    http = baseline_data.get('http', {})
    
    table.add_row("Total Connections", str(conn.get('total_connections', 0)))
    table.add_row("Conn/min (mean)", f"{conn.get('connections_per_minute_mean', 0):.2f}")
    table.add_row("Unique Source IPs", str(conn.get('unique_src_ips', 0)))
    table.add_row("Total HTTP Requests", str(http.get('total_requests', 0)))
    table.add_row("HTTP Req/min (mean)", f"{http.get('requests_per_minute_mean', 0):.2f}")
    table.add_row("HTTP Error Rate", f"{http.get('error_rate', 0):.2%}")
    
    console.print(table)
    console.print(f"\n[green]✓ Baseline saved to {output_path}[/green]")


@cli.command()
@click.option('--baseline-file', '-b', default='baseline.json', help='Baseline file to use')
@click.option('--output', '-o', default='anomalies.json', help='Anomaly report output')
@click.pass_context
def detect(ctx, baseline_file, output):
    """
    Run anomaly detection against current logs.
    
    Compares current traffic against the baseline to detect anomalies.
    """
    log_dir = ctx.obj['log_dir']
    output_dir = ctx.obj['output_dir']
    baseline_path = Path(output_dir) / baseline_file
    output_path = Path(output_dir) / output
    
    console.print(Panel(
        f"[bold blue]Anomaly Detection[/bold blue]\n"
        f"Baseline: {baseline_path}\n"
        f"Log directory: {log_dir}",
        title="SecuriSphere Analyzer"
    ))
    
    # Load baseline
    if not baseline_path.exists():
        console.print(f"[red]Error: Baseline file not found: {baseline_path}[/red]")
        console.print("[yellow]Run 'baseline' command first to create a baseline.[/yellow]")
        return
    
    with open(baseline_path, 'r') as f:
        baseline_data = json.load(f)
    
    with console.status("[bold green]Analyzing traffic..."):
        detector = AnomalyDetector(baseline_data, log_dir)
        anomalies = detector.detect_all_anomalies()
        report = detector.generate_report(anomalies, str(output_path))
    
    # Display results
    _display_anomaly_summary(report)
    _display_anomaly_table(anomalies[:20])  # Show top 20
    
    console.print(f"\n[green]✓ Full report saved to {output_path}[/green]")


@cli.command()
@click.option('--baseline-file', '-b', default='baseline.json', help='Baseline file to use')
@click.option('--interval', '-i', default=30, help='Check interval in seconds')
@click.pass_context
def watch(ctx, baseline_file, interval):
    """
    Continuously monitor logs for anomalies.
    
    Runs in real-time, checking for new anomalies periodically.
    """
    log_dir = ctx.obj['log_dir']
    output_dir = ctx.obj['output_dir']
    baseline_path = Path(output_dir) / baseline_file
    
    console.print(Panel(
        f"[bold blue]Real-time Anomaly Monitoring[/bold blue]\n"
        f"Log directory: {log_dir}\n"
        f"Check interval: {interval}s\n"
        f"Press Ctrl+C to stop",
        title="SecuriSphere Analyzer"
    ))
    
    # Check for baseline
    if not baseline_path.exists():
        console.print("[yellow]No baseline found. Building initial baseline...[/yellow]")
        builder = BaselineBuilder(log_dir)
        baseline_data = builder.build_full_baseline()
        builder.save_baseline(baseline_data, str(baseline_path))
    else:
        with open(baseline_path, 'r') as f:
            baseline_data = json.load(f)
    
    detector = AnomalyDetector(baseline_data, log_dir)
    seen_anomalies = set()
    
    console.print("[green]✓ Monitoring started...[/green]\n")
    
    try:
        while True:
            anomalies = detector.detect_all_anomalies()
            
            # Filter for new anomalies
            new_anomalies = []
            for a in anomalies:
                key = f"{a.anomaly_type.value}:{a.source_ip}:{a.timestamp}"
                if key not in seen_anomalies:
                    seen_anomalies.add(key)
                    new_anomalies.append(a)
            
            if new_anomalies:
                console.print(f"\n[bold red]⚠ {len(new_anomalies)} NEW ANOMALIES DETECTED[/bold red]")
                _display_anomaly_table(new_anomalies)
            else:
                console.print(f"[dim]{datetime.now().strftime('%H:%M:%S')} - No new anomalies[/dim]", end='\r')
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped.[/yellow]")


@cli.command()
@click.option('--anomaly-file', '-a', default='anomalies.json', help='Anomaly report file')
@click.pass_context
def report(ctx, anomaly_file):
    """
    Display anomaly report summary.
    
    Reads and displays a previously generated anomaly report.
    """
    output_dir = ctx.obj['output_dir']
    report_path = Path(output_dir) / anomaly_file
    
    if not report_path.exists():
        console.print(f"[red]Error: Report file not found: {report_path}[/red]")
        return
    
    with open(report_path, 'r') as f:
        report_data = json.load(f)
    
    console.print(Panel(
        f"[bold blue]Anomaly Report[/bold blue]\n"
        f"Generated: {report_data.get('generated_at', 'Unknown')}",
        title="SecuriSphere Analyzer"
    ))
    
    _display_anomaly_summary(report_data)
    
    anomalies = [
        Anomaly(
            anomaly_type=a['anomaly_type'],
            severity=a['severity'],
            timestamp=a['timestamp'],
            source_ip=a.get('source_ip', ''),
            destination_ip=a.get('destination_ip', ''),
            description=a.get('description', '')
        )
        for a in report_data.get('anomalies', [])
    ]
    
    _display_anomaly_table(anomalies[:30])


def _display_anomaly_summary(report: dict):
    """Display anomaly summary statistics."""
    table = Table(title="Detection Summary")
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="green")
    
    table.add_row("Total Anomalies", str(report.get('total_anomalies', 0)))
    
    # By severity
    by_severity = report.get('by_severity', {})
    for severity in ['critical', 'high', 'medium', 'low']:
        count = by_severity.get(severity, 0)
        if count > 0:
            color = {
                'critical': 'red bold',
                'high': 'red',
                'medium': 'yellow',
                'low': 'green'
            }.get(severity, 'white')
            table.add_row(f"  {severity.upper()}", f"[{color}]{count}[/{color}]")
    
    console.print(table)


def _display_anomaly_table(anomalies: list):
    """Display anomaly details in a table."""
    if not anomalies:
        console.print("[dim]No anomalies to display[/dim]")
        return
    
    table = Table(title=f"Anomalies ({len(anomalies)})")
    table.add_column("Time", style="dim", width=20)
    table.add_column("Severity", width=10)
    table.add_column("Type", style="cyan", width=20)
    table.add_column("Source IP", width=15)
    table.add_column("Description", width=50)
    
    for a in anomalies:
        severity = a.severity if isinstance(a.severity, str) else a.severity.value
        anomaly_type = a.anomaly_type if isinstance(a.anomaly_type, str) else a.anomaly_type.value
        
        severity_color = {
            'critical': 'red bold',
            'high': 'red',
            'medium': 'yellow',
            'low': 'green'
        }.get(severity, 'white')
        
        table.add_row(
            str(a.timestamp)[:19],
            f"[{severity_color}]{severity.upper()}[/{severity_color}]",
            anomaly_type,
            a.source_ip or "-",
            a.description[:50] + "..." if len(a.description) > 50 else a.description
        )
    
    console.print(table)


if __name__ == "__main__":
    cli()
