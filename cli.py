import argparse
import json
from datetime import datetime, timedelta
from typing import Optional
from database import get_db
from threat_analyzer import ThreatAnalyzer
from threat_aggregation import ThreatAggregator
from threat_visualizer import ThreatVisualizer
from data_manager import ThreatDataManager
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.progress import Progress

console = Console()

class ThreatIntelligenceCLI:
    def __init__(self):
        self.db = next(get_db())
        self.analyzer = ThreatAnalyzer()
        self.aggregator = ThreatAggregator()
        self.visualizer = ThreatVisualizer()
        self.data_manager = ThreatDataManager()

    def close(self):
        self.db.close()

    def scan_ip(self, ip_address: str):
        """Scan a new IP address"""
        with Progress() as progress:
            task = progress.add_task(f"[cyan]Scanning IP {ip_address}...", total=100)
            
            # Collect threat data
            progress.update(task, advance=30)
            threat_data = self.aggregator.aggregate_threat_data(ip_address)
            
            progress.update(task, advance=30)
            # Save to database
            ip_record = self.data_manager.save_threat_data(self.db, ip_address, threat_data)
            
            progress.update(task, advance=40)

        # Display results
        self.display_ip_details(ip_address)

    def display_ip_details(self, ip_address: str):
        """Display detailed information about an IP address"""
        details = self.analyzer.get_ip_details(self.db, ip_address)
        
        if "error" in details:
            console.print(f"[red]Error: {details['error']}")
            return

        # Create main IP info panel
        ip_info = Table.grid(padding=1)
        ip_info.add_row("IP Address:", f"[cyan]{details['ip_address']}")
        ip_info.add_row("First Seen:", f"[yellow]{details['first_seen']}")
        ip_info.add_row("Last Updated:", f"[yellow]{details['last_updated']}")
        ip_info.add_row("Threat Score:", f"[red]{details['overall_threat_score']:.2f}")
        ip_info.add_row("Malicious:", f"[red]{str(details['is_malicious'])}")

        console.print(Panel(ip_info, title="IP Information", box=box.ROUNDED))

        # Display source-specific information
        if details['threat_data']['virustotal']:
            vt_table = Table(title="VirusTotal Data", box=box.MINIMAL_DOUBLE_HEAD)
            vt_table.add_column("Metric", style="cyan")
            vt_table.add_column("Value", style="yellow")
            vt = details['threat_data']['virustotal']
            vt_table.add_row("Malicious", str(vt['malicious_count']))
            vt_table.add_row("Suspicious", str(vt['suspicious_count']))
            vt_table.add_row("Harmless", str(vt['harmless_count']))
            console.print(vt_table)

        if details['threat_data']['shodan']:
            shodan_table = Table(title="Shodan Data", box=box.MINIMAL_DOUBLE_HEAD)
            shodan_table.add_column("Metric", style="cyan")
            shodan_table.add_column("Value", style="yellow")
            shodan = details['threat_data']['shodan']
            shodan_table.add_row("Open Ports", ", ".join(map(str, shodan['ports'])))
            shodan_table.add_row("Vulnerabilities", ", ".join(shodan['vulnerabilities']))
            console.print(shodan_table)

        if details['threat_data']['alienvault']:
            av_table = Table(title="AlienVault Data", box=box.MINIMAL_DOUBLE_HEAD)
            av_table.add_column("Metric", style="cyan")
            av_table.add_column("Value", style="yellow")
            av = details['threat_data']['alienvault']
            av_table.add_row("Pulse Count", str(av['pulse_count']))
            av_table.add_row("Reputation", str(av['reputation']))
            av_table.add_row("Activities", ", ".join(av['activity_types']))
            console.print(av_table)

    def list_high_risk_ips(self, min_score: float = 70.0):
        """List all high-risk IPs"""
        high_risk = self.analyzer.get_high_risk_ips(self.db, min_score)
        
        table = Table(title=f"High Risk IPs (Score >= {min_score})", box=box.MINIMAL_DOUBLE_HEAD)
        table.add_column("IP Address", style="cyan")
        table.add_column("Threat Score", style="red")
        table.add_column("Last Updated", style="yellow")

        for ip in high_risk:
            table.add_row(
                ip['ip_address'],
                f"{ip['threat_score']:.2f}",
                ip['last_updated']
            )

        console.print(table)

    def show_statistics(self):
        """Display overall threat intelligence statistics"""
        stats = self.analyzer.get_statistics(self.db)
        
        table = Table(title="Threat Intelligence Statistics", box=box.MINIMAL_DOUBLE_HEAD)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="yellow")

        table.add_row("Total IPs Tracked", str(stats['total_ips_tracked']))
        table.add_row("Malicious IPs", str(stats['malicious_ips_count']))
        table.add_row("Average Threat Score", f"{stats['average_threat_score']:.2f}")
        table.add_row("Malicious IP Percentage", f"{stats['malicious_ip_percentage']:.2f}%")

        console.print(table)

    def generate_visualizations(self):
        """Generate all visualization plots"""
        with Progress() as progress:
            task = progress.add_task("[cyan]Generating visualizations...", total=100)
            
            report = self.visualizer.create_comprehensive_report()
            
            progress.update(task, completed=100)

        console.print("\n[green]Visualizations generated successfully!")
        for plot_type, filepath in report["plots"].items():
            console.print(f"[yellow]{plot_type}:[/yellow] {filepath}")

def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Platform CLI")
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Scan IP command
    scan_parser = subparsers.add_parser('scan', help='Scan an IP address')
    scan_parser.add_argument('ip', help='IP address to scan')

    # View IP details command
    view_parser = subparsers.add_parser('view', help='View IP details')
    view_parser.add_argument('ip', help='IP address to view')

    # List high risk IPs command
    list_parser = subparsers.add_parser('list-high-risk', help='List high risk IPs')
    list_parser.add_argument('--min-score', type=float, default=70.0, 
                            help='Minimum threat score (default: 70.0)')

    # Show statistics command
    subparsers.add_parser('stats', help='Show threat intelligence statistics')

    # Generate visualizations command
    subparsers.add_parser('viz', help='Generate threat intelligence visualizations')

    args = parser.parse_args()

    cli = ThreatIntelligenceCLI()
    try:
        if args.command == 'scan':
            cli.scan_ip(args.ip)
        elif args.command == 'view':
            cli.display_ip_details(args.ip)
        elif args.command == 'list-high-risk':
            cli.list_high_risk_ips(args.min_score)
        elif args.command == 'stats':
            cli.show_statistics()
        elif args.command == 'viz':
            cli.generate_visualizations()
        else:
            parser.print_help()
    finally:
        cli.close()

if __name__ == '__main__':
    main() 