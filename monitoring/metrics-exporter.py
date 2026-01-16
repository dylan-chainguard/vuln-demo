#!/usr/bin/env python3
"""
Simple Prometheus exporter for vulnerability metrics
"""
import json
import time
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            try:
                metrics_file = Path('/metrics/vulnerability-metrics.json')
                with open(metrics_file) as f:
                    data = json.load(f)

                # Generate Prometheus metrics
                metrics = []

                # Summary metrics
                summary = data['summary']
                metrics.append(f'vulnerability_total {summary["total_vulnerabilities"]}')
                metrics.append(f'vulnerability_critical {summary["by_severity"]["critical"]}')
                metrics.append(f'vulnerability_high {summary["by_severity"]["high"]}')
                metrics.append(f'vulnerability_medium {summary["by_severity"]["medium"]}')
                metrics.append(f'vulnerability_low {summary["by_severity"]["low"]}')

                # Per-image metrics
                for image in data['images']:
                    name = image['name']
                    vulns = image['vulnerabilities']
                    metrics.append(f'vulnerability_by_image{{image="{name}",severity="critical"}} {vulns["critical"]}')
                    metrics.append(f'vulnerability_by_image{{image="{name}",severity="high"}} {vulns["high"]}')
                    metrics.append(f'vulnerability_by_image{{image="{name}",severity="medium"}} {vulns["medium"]}')
                    metrics.append(f'vulnerability_by_image{{image="{name}",severity="low"}} {vulns["low"]}')
                    metrics.append(f'vulnerability_by_image_total{{image="{name}"}} {vulns["total"]}')

                response = '\n'.join(metrics) + '\n'

                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write(response.encode('utf-8'))

            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f'Error: {str(e)}\n'.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        print(f"{self.address_string()} - [{self.log_date_time_string()}] {format%args}")

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8000), MetricsHandler)
    print('Metrics exporter running on port 8000...')
    server.serve_forever()
