import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from datetime import datetime
import json
from typing import Dict, List
from threat_analyzer import ThreatAnalyzer
from database import get_db
import os
import numpy as np

class ThreatVisualizer:
    """Creates visualizations for threat intelligence data"""

    def __init__(self):
        # Use a built-in style instead of seaborn
        plt.style.use('ggplot')  # Using ggplot style which is similar to seaborn
        
        # Create output directory if it doesn't exist
        self.output_dir = "threat_visualizations"
        os.makedirs(self.output_dir, exist_ok=True)

    def save_plot(self, name: str):
        """Save the current plot to the output directory"""
        plt.tight_layout()
        filepath = os.path.join(self.output_dir, f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        return filepath

    def plot_threat_trends(self, trend_data: Dict):
        """
        Create a line plot showing threat score trends over time
        """
        df = pd.DataFrame(trend_data['trend_data'])
        # Convert string dates to datetime objects for plotting
        df['date'] = pd.to_datetime(df['date'])

        plt.figure(figsize=(12, 6))
        
        # Plot average threat score
        ax1 = plt.gca()
        ax1.plot(df['date'], df['average_threat_score'], 
                marker='o', linewidth=2, label='Average Threat Score')
        ax1.set_xlabel('Date')
        ax1.set_ylabel('Average Threat Score', color='tab:blue')
        ax1.tick_params(axis='y', labelcolor='tab:blue')

        # Plot number of IPs analyzed on secondary y-axis
        ax2 = ax1.twinx()
        ax2.plot(df['date'], df['ips_analyzed'], 
                color='tab:orange', linestyle='--', label='IPs Analyzed')
        ax2.set_ylabel('Number of IPs Analyzed', color='tab:orange')
        ax2.tick_params(axis='y', labelcolor='tab:orange')

        plt.title('Threat Score Trends Over Time')
        
        # Add legend
        lines1, labels1 = ax1.get_legend_handles_labels()
        lines2, labels2 = ax2.get_legend_handles_labels()
        ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

        return self.save_plot('threat_trends')

    def plot_source_correlation(self, correlation_data: Dict):
        """
        Create a heatmap showing correlations between different sources
        """
        sources = ['VirusTotal', 'AlienVault', 'Shodan']
        corr_matrix = [
            [1.0, correlation_data['correlations']['virustotal_alienvault'], 
             correlation_data['correlations']['virustotal_shodan']],
            [correlation_data['correlations']['virustotal_alienvault'], 1.0, 
             correlation_data['correlations']['alienvault_shodan']],
            [correlation_data['correlations']['virustotal_shodan'], 
             correlation_data['correlations']['alienvault_shodan'], 1.0]
        ]

        plt.figure(figsize=(8, 6))
        sns.heatmap(corr_matrix, annot=True, cmap='RdYlBu', center=0,
                   xticklabels=sources, yticklabels=sources, vmin=-1, vmax=1)
        plt.title('Correlation Between Threat Intelligence Sources')

        return self.save_plot('source_correlation')

    def plot_port_exposure(self, port_data: Dict):
        """
        Create a bar plot showing most common open ports
        """
        df = pd.DataFrame(port_data['port_statistics'])
        top_ports = df.nlargest(10, 'count')

        plt.figure(figsize=(12, 6))
        bars = plt.bar(range(len(top_ports)), top_ports['count'])
        plt.xticks(range(len(top_ports)), 
                  [f"{row['port']}\n({row['service']})" for _, row in top_ports.iterrows()],
                  rotation=45)

        # Color high-risk ports differently
        for i, bar in enumerate(bars):
            if top_ports.iloc[i]['is_high_risk']:
                bar.set_color('red')

        plt.xlabel('Port (Service)')
        plt.ylabel('Number of Occurrences')
        plt.title('Top 10 Most Common Open Ports')

        # Add legend
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='red', label='High Risk'),
            Patch(facecolor='tab:blue', label='Normal')
        ]
        plt.legend(handles=legend_elements)

        return self.save_plot('port_exposure')

    def plot_threat_patterns(self, pattern_data: Dict):
        """
        Create visualizations for threat patterns
        """
        # Check if we have any activity patterns
        if not pattern_data.get('activity_patterns') or len(pattern_data['activity_patterns']) == 0:
            # Create an empty plot with a message
            plt.figure(figsize=(12, 6))
            plt.text(0.5, 0.5, 'No threat pattern data available', 
                    horizontalalignment='center',
                    verticalalignment='center',
                    transform=plt.gca().transAxes)
            plt.title('Threat Patterns')
            return self.save_plot('threat_patterns')

        # Convert to DataFrame
        df = pd.DataFrame(pattern_data['activity_patterns'])
        
        # Check if required columns exist
        if 'activity' not in df.columns or 'count' not in df.columns:
            plt.figure(figsize=(12, 6))
            plt.text(0.5, 0.5, 'Invalid threat pattern data format', 
                    horizontalalignment='center',
                    verticalalignment='center',
                    transform=plt.gca().transAxes)
            plt.title('Threat Patterns')
            return self.save_plot('threat_patterns')

        # Plot top activities by count
        plt.figure(figsize=(12, 6))
        
        # Get top activities (up to 10)
        n_activities = min(10, len(df))
        top_activities = df.nlargest(n_activities, 'count')
        
        # Create color gradient based on average threat score
        colors = plt.cm.YlOrRd(np.linspace(0.2, 0.8, len(top_activities)))
        
        # Sort by count and plot
        bars = plt.bar(range(len(top_activities)), top_activities['count'])
        
        # Color bars
        for i, bar in enumerate(bars):
            bar.set_color(colors[i])
            
        plt.xticks(range(len(top_activities)), 
                  top_activities['activity'], 
                  rotation=45, 
                  ha='right')
        plt.xlabel('Activity Type')
        plt.ylabel('Number of Occurrences')
        plt.title('Threat Activities')

        return self.save_plot('threat_patterns')

    def create_comprehensive_report(self):
        """
        Generate a comprehensive visual report of all threat analyses
        """
        db = next(get_db())
        plots = {}
        
        try:
            # Create all visualizations with error handling
            try:
                trend_data = ThreatAnalyzer.analyze_threat_trends(db)
                plots['threat_trends'] = self.plot_threat_trends(trend_data)
            except Exception as e:
                print(f"Error generating threat trends plot: {e}")

            try:
                correlation_data = ThreatAnalyzer.analyze_source_correlation(db)
                plots['source_correlation'] = self.plot_source_correlation(correlation_data)
            except Exception as e:
                print(f"Error generating source correlation plot: {e}")

            try:
                port_data = ThreatAnalyzer.analyze_port_exposure(db)
                plots['port_exposure'] = self.plot_port_exposure(port_data)
            except Exception as e:
                print(f"Error generating port exposure plot: {e}")

            try:
                pattern_data = ThreatAnalyzer.analyze_threat_patterns(db)
                plots['threat_patterns'] = self.plot_threat_patterns(pattern_data)
            except Exception as e:
                print(f"Error generating threat patterns plot: {e}")

            return {
                "plots": plots,
                "timestamp": datetime.now().isoformat(),
                "plots_generated": len(plots)
            }

        finally:
            db.close()

# Example usage
if __name__ == "__main__":
    visualizer = ThreatVisualizer()
    
    print("Generating comprehensive threat intelligence report...")
    report = visualizer.create_comprehensive_report()
    
    print("\nVisualization files generated:")
    for plot_type, filepath in report["plots"].items():
        print(f"{plot_type}: {filepath}") 