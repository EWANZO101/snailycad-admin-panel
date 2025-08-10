# Configuration file for SnailyCAD Admin Panel

# IP addresses that are allowed to access the application
# Add your IP addresses here
WHITELISTED_IPS = [
    '127.0.0.1',        # localhost
    '::1',              # localhost IPv6
    '192.168.1.100',    # Example IP - replace with your actual IPs
    # Add more IPs as needed
]

# Database password for PostgreSQL operations
DB_PASSWORD = 'zVw&HJBf8W8tmBu'

# SnailyCAD specific settings
SNAILYCAD_PATH = '/home/snaily-cadv4'
SNAILYCAD_ENV_FILE = '/home/snaily-cadv4/.env'

# Database settings
DB_NAME = 'snaily-cad-v4'
DB_USER = 'postgres'
DB_HOST = 'localhost'
DB_PORT = 5432

# Redirect URL for non-whitelisted IPs
REDIRECT_URL = 'https://acd.swiftpeakhosting.com/'

# You can add more configuration variables here as needed
