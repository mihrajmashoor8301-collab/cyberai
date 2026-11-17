"""Report Generator - Generate pentest reports in multiple formats"""

import os
import json
from datetime import datetime


class ReportGenerator:
    def __init__(self):
        self.reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports')
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def generate(self, data, output_path=None, format='html'):
        """Generate report in specified format"""
        if not output_path:
            output_path = os.path.join(
                self.reports_dir,
                f"cyberai_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
            )
        
        # Ensure output directory exists
        output_dir = os.path.dirname(os.path.abspath(output_path))
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        if format == 'html':
            self._generate_html(data, output_path)
        elif format == 'json':
            self._generate_json(data, output_path)
        elif format == 'pdf':
            self._generate_pdf(data, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        return output_path
    
    def _generate_html(self, data, output_path):
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberAI Pentest Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .header .meta {{
            margin-top: 10px;
            opacity: 0.8;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-card .number {{
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .info {{ color: #17a2b8; }}
        .section {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .section h2 {{
            border-bottom: 2px solid #1a1a2e;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        .finding {{
            border-left: 4px solid #ddd;
            padding: 15px;
            margin-bottom: 15px;
            background: #fafafa;
            border-radius: 0 4px 4px 0;
        }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        .finding.info {{ border-left-color: #17a2b8; }}
        .severity {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            color: white;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .severity.CRITICAL {{ background: #dc3545; }}
        .severity.HIGH {{ background: #fd7e14; }}
        .severity.MEDIUM {{ background: #ffc107; color: #333; }}
        .severity.LOW {{ background: #28a745; }}
        .severity.INFO {{ background: #17a2b8; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #1a1a2e;
            color: white;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
        @media print {{
            body {{ background: white; }}
            .section {{ box-shadow: none; border: 1px solid #ddd; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ CyberAI Pentest Report</h1>
        <div class="meta">
            <p>Target: {data.get('target', 'N/A')}</p>
            <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Generated by CyberAI Pentest Toolkit</p>
        </div>
    </div>
    
    <div class="summary">
        <div class="summary-card">
            <div class="label">Total Findings</div>
            <div class="number">{data.get('summary', {}).get('total', len(data.get('findings', [])))}</div>
        </div>
        <div class="summary-card">
            <div class="label">Critical</div>
            <div class="number critical">{data.get('summary', {}).get('critical', 0)}</div>
        </div>
        <div class="summary-card">
            <div class="label">High</div>
            <div class="number high">{data.get('summary', {}).get('high', 0)}</div>
        </div>
        <div class="summary-card">
            <div class="label">Medium</div>
            <div class="number medium">{data.get('summary', {}).get('medium', 0)}</div>
        </div>
        <div class="summary-card">
            <div class="label">Low/Info</div>
            <div class="number low">{data.get('summary', {}).get('info', 0)}</div>
        </div>
    </div>
"""
        
        # Open ports section
        if 'scans' in data and 'network' in data['scans']:
            ports = data['scans']['network'].get('ports', [])
            if ports:
                html += f"""
    <div class="section">
        <h2>📡 Open Ports</h2>
        <table>
            <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>Status</th>
                <th>Service</th>
                <th>Version</th>
            </tr>
"""
                for port in ports:
                    html += f"""
            <tr>
                <td>{port['port']}</td>
                <td>{port['protocol']}</td>
                <td>{port['state']}</td>
                <td>{port['service']}</td>
                <td>{port.get('version', 'N/A')}</td>
            </tr>
"""
                html += """
        </table>
    </div>
"""
        
        # Findings section
        findings = data.get('findings', [])
        if findings:
            html += f"""
    <div class="section">
        <h2>🔍 Findings</h2>
"""
            for i, finding in enumerate(findings, 1):
                severity = finding.get('severity', 'INFO').upper()
                html += f"""
        <div class="finding {severity.lower()}">
            <span class="severity {severity}">{severity}</span>
            <strong>{i}. {finding.get('title', 'No title')}</strong>
            <p>{finding.get('description', 'No description')}</p>
"""
                if finding.get('url'):
                    html += f"            <p><strong>URL:</strong> {finding['url']}</p>\n"
                if finding.get('recommendation'):
                    html += f"            <p><strong>Recommendation:</strong> {finding['recommendation']}</p>\n"
                html += "        </div>\n"
            html += "    </div>\n"
        
        html += f"""
    <div class="footer">
        <p>Generated by <strong>CyberAI Pentest Toolkit</strong> | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>CONFIDENTIAL - For authorized use only</p>
    </div>
</body>
</html>
"""
        
        with open(output_path, 'w') as f:
            f.write(html)
        
        print(f"[+] HTML report saved to: {output_path}")
    
    def _generate_json(self, data, output_path):
        """Generate JSON report"""
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        print(f"[+] JSON report saved to: {output_path}")
    
    def _generate_pdf(self, data, output_path):
        """Generate PDF report using reportlab"""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            story.append(Paragraph("CyberAI Pentest Report", styles['Title']))
            story.append(Spacer(1, 12))
            story.append(Paragraph(f"Target: {data.get('target', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Spacer(1, 24))
            
            # Summary
            summary = data.get('summary', {})
            story.append(Paragraph("Summary", styles['Heading2']))
            summary_data = [
                ['Metric', 'Count'],
                ['Total Findings', str(summary.get('total', 0))],
                ['Critical', str(summary.get('critical', 0))],
                ['High', str(summary.get('high', 0))],
                ['Medium', str(summary.get('medium', 0))],
                ['Low/Info', str(summary.get('info', 0))],
            ]
            t = Table(summary_data)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(t)
            story.append(Spacer(1, 24))
            
            # Findings
            findings = data.get('findings', [])
            if findings:
                story.append(Paragraph("Findings", styles['Heading2']))
                for i, finding in enumerate(findings, 1):
                    story.append(Paragraph(f"{i}. {finding.get('title', 'N/A')}", styles['Heading3']))
                    story.append(Paragraph(f"<b>Severity:</b> {finding.get('severity', 'N/A')}", styles['Normal']))
                    story.append(Paragraph(f"<b>Description:</b> {finding.get('description', 'N/A')}", styles['Normal']))
                    if finding.get('recommendation'):
                        story.append(Paragraph(f"<b>Recommendation:</b> {finding['recommendation']}", styles['Normal']))
                    story.append(Spacer(1, 12))
            
            # Build PDF
            doc.build(story)
            print(f"[+] PDF report saved to: {output_path}")
        
        except ImportError:
            print("[-] reportlab not installed. Install with: pip install reportlab")
            print(f"[-] Falling back to JSON report")
            self._generate_json(data, output_path.replace('.pdf', '.json'))
