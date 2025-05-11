import multiprocessing
import os

# Server socket
bind = "127.0.0.1:5000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'sync'
worker_connections = 1000
timeout = 30
keepalive = 2

# Logging
accesslog = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'access.log')
errorlog = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'error.log')
loglevel = 'info'

# Process naming
proc_name = 'cloudflare_scanner'

# SSL
keyfile = None
certfile = None

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Working directory
chdir = os.path.dirname(os.path.abspath(__file__)) 