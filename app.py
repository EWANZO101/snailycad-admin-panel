from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
import subprocess
import shutil
from datetime import datetime
import re
import tempfile
import importlib.util
import sys
import platform
import psutil
import secrets
from functools import wraps
import logging
from config import WHITELISTED_IPS, DB_PASSWORD

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/snaily-admin/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

ENV_FILE_PATH = '/home/snaily-cadv4/.env'
NGINX_CONF_PATH = '/etc/nginx/nginx.conf'

def check_ip():
    """Check if the request IP is whitelisted"""
    client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    if client_ip not in WHITELISTED_IPS:
        logger.warning(f"Access denied for IP: {client_ip}")
        return False
    return True

@app.before_request
def before_request():
    """Check IP whitelist before each request"""
    if not check_ip():
        return redirect('https://acd.swiftpeakhosting.com/')

def require_sudo():
    """Decorator to check if operations requiring sudo can be performed"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Test sudo access
                result = subprocess.run(['sudo', '-n', 'true'], 
                                      capture_output=True, timeout=5)
                if result.returncode != 0:
                    return jsonify({
                        'success': False, 
                        'error': 'Sudo access required but not available'
                    }), 403
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Sudo check failed: {e}")
                return jsonify({
                    'success': False, 
                    'error': 'Unable to verify sudo access'
                }), 500
        return decorated_function
    return decorator

def parse_env_file(file_path):
    """Parse .env file into key-value pairs"""
    env_vars = {}
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '=' in line:
                            key, value = line.split('=', 1)
                            env_vars[key.strip()] = value.strip()
        except Exception as e:
            logger.error(f"Error parsing env file: {e}")
    return env_vars

def write_env_file(file_path, env_vars):
    """Write environment variables back to .env file"""
    try:
        # Create backup
        if os.path.exists(file_path):
            backup_path = f"{file_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(file_path, backup_path)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            for key, value in env_vars.items():
                f.write(f"{key}={value}\n")
        
        logger.info(f"Environment file updated: {file_path}")
        return True
    except Exception as e:
        logger.error(f"Error writing env file: {e}")
        return False

# Template functions
@app.template_global()
def moment():
    """Mock moment function for templates"""
    class MockMoment:
        def format(self, fmt):
            return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return MockMoment()

@app.template_global()
def python_version():
    """Get Python version"""
    return f"Python {platform.python_version()}"

@app.route('/')
def editor():
    """Main .env editor page"""
    try:
        env_vars = parse_env_file(ENV_FILE_PATH)
        return render_template('editor.html', env_vars=env_vars)
    except Exception as e:
        logger.error(f"Error in editor route: {e}")
        flash(f'Error loading editor: {str(e)}', 'error')
        return render_template('editor.html', env_vars={})

@app.route('/save-env', methods=['POST'])
def save_env():
    """Save .env file changes"""
    try:
        env_vars = {}
        form_data = request.form.to_dict()
        
        # Process form data
        for key, value in form_data.items():
            if key.startswith('key_'):
                index = key.split('_')[1]
                var_key = form_data.get(f'key_{index}', '').strip()
                var_value = form_data.get(f'value_{index}', '').strip()
                if var_key:  # Only add if key is not empty
                    env_vars[var_key] = var_value
        
        if write_env_file(ENV_FILE_PATH, env_vars):
            flash('SnailyCAD environment file saved successfully!', 'success')
        else:
            flash('Error saving environment file', 'error')
    except Exception as e:
        logger.error(f"Error saving env: {e}")
        flash(f'Error saving file: {str(e)}', 'error')
    
    return redirect(url_for('editor'))

@app.route('/live-editor')
def live_editor():
    """Live .env file editor with direct text editing"""
    try:
        if os.path.exists(ENV_FILE_PATH):
            with open(ENV_FILE_PATH, 'r', encoding='utf-8') as f:
                env_content = f.read()
        else:
            env_content = "# SnailyCAD Environment Configuration\n# Add your variables below\n"
        
        # Get file metadata
        file_stats = os.stat(ENV_FILE_PATH) if os.path.exists(ENV_FILE_PATH) else None
        last_modified = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S') if file_stats else 'File not found'
        
        return render_template('live_editor.html', 
                             env_content=env_content, 
                             last_modified=last_modified,
                             file_path=ENV_FILE_PATH)
    except Exception as e:
        logger.error(f"Error in live editor: {e}")
        flash(f'Error reading .env file: {str(e)}', 'error')
        return render_template('live_editor.html', env_content='', last_modified='Error', file_path=ENV_FILE_PATH)

@app.route('/save-live-env', methods=['POST'])
def save_live_env():
    """Save .env file content directly"""
    try:
        env_content = request.form.get('env_content', '')
        
        # Create backup with timestamp
        if os.path.exists(ENV_FILE_PATH):
            backup_path = f"{ENV_FILE_PATH}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(ENV_FILE_PATH, backup_path)
        
        # Write the content directly
        with open(ENV_FILE_PATH, 'w', encoding='utf-8') as f:
            f.write(env_content)
        
        # Get updated file info
        file_stats = os.stat(ENV_FILE_PATH)
        last_modified = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        
        logger.info("Live environment file saved successfully")
        return jsonify({
            'success': True,
            'message': 'Environment file saved successfully!',
            'last_modified': last_modified
        })
    except Exception as e:
        logger.error(f"Error saving live env: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/validate-env', methods=['POST'])
def validate_env():
    """Validate .env file syntax in real-time"""
    try:
        env_content = request.form.get('env_content', '')
        errors = []
        warnings = []
        
        lines = env_content.split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if line and not line.startswith('#'):
                if '=' not in line:
                    errors.append(f"Line {line_num}: Missing '=' separator")
                else:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Check for common issues
                    if not key:
                        errors.append(f"Line {line_num}: Empty variable name")
                    elif not re.match(r'^[A-Z_][A-Z0-9_]*$', key):
                        warnings.append(f"Line {line_num}: Variable name '{key}' should be uppercase with underscores")
                    
                    # Check for unquoted values with spaces
                    if value and ' ' in value and not (value.startswith('"') and value.endswith('"')):
                        warnings.append(f"Line {line_num}: Value contains spaces but is not quoted")
        
        return jsonify({
            'success': True,
            'errors': errors,
            'warnings': warnings,
            'is_valid': len(errors) == 0
        })
    except Exception as e:
        logger.error(f"Error validating env: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/check-file-changes', methods=['GET'])
def check_file_changes():
    """Check if .env file has been modified externally"""
    try:
        if os.path.exists(ENV_FILE_PATH):
            file_stats = os.stat(ENV_FILE_PATH)
            last_modified = file_stats.st_mtime
            
            return jsonify({
                'success': True,
                'last_modified': last_modified,
                'last_modified_formatted': datetime.fromtimestamp(last_modified).strftime('%Y-%m-%d %H:%M:%S')
            })
        else:
            return jsonify({
                'success': False,
                'error': 'File not found'
            })
    except Exception as e:
        logger.error(f"Error checking file changes: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/reload-env', methods=['GET'])
def reload_env():
    """Reload .env file content"""
    try:
        if os.path.exists(ENV_FILE_PATH):
            with open(ENV_FILE_PATH, 'r', encoding='utf-8') as f:
                env_content = f.read()
            
            file_stats = os.stat(ENV_FILE_PATH)
            last_modified = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            
            return jsonify({
                'success': True,
                'content': env_content,
                'last_modified': last_modified
            })
        else:
            return jsonify({
                'success': False,
                'error': 'File not found'
            })
    except Exception as e:
        logger.error(f"Error reloading env: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/create-backup', methods=['POST'])
def create_backup():
    """Create a manual backup of the .env file"""
    try:
        if not os.path.exists(ENV_FILE_PATH):
            return jsonify({'success': False, 'error': 'Source file not found'})
        
        backup_name = request.form.get('backup_name', '')
        if backup_name:
            # Sanitize backup name
            backup_name = re.sub(r'[^a-zA-Z0-9_-]', '_', backup_name)
            backup_path = f"{ENV_FILE_PATH}.backup.{backup_name}.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        else:
            backup_path = f"{ENV_FILE_PATH}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        shutil.copy2(ENV_FILE_PATH, backup_path)
        logger.info(f"Backup created: {backup_path}")
        
        return jsonify({
            'success': True,
            'backup_path': backup_path,
            'message': f'Backup created: {os.path.basename(backup_path)}'
        })
    except Exception as e:
        logger.error(f"Error creating backup: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/list-backups', methods=['GET'])
def list_backups():
    """List all backup files"""
    try:
        backup_dir = os.path.dirname(ENV_FILE_PATH)
        backup_files = []
        
        for file in os.listdir(backup_dir):
            if file.startswith(os.path.basename(ENV_FILE_PATH) + '.backup'):
                file_path = os.path.join(backup_dir, file)
                file_stats = os.stat(file_path)
                backup_files.append({
                    'name': file,
                    'path': file_path,
                    'size': file_stats.st_size,
                    'modified': datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
        
        # Sort by modification time (newest first)
        backup_files.sort(key=lambda x: x['modified'], reverse=True)
        
        return jsonify({'success': True, 'backups': backup_files})
    except Exception as e:
        logger.error(f"Error listing backups: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/restore-backup', methods=['POST'])
def restore_backup():
    """Restore from a backup file"""
    try:
        backup_name = request.form.get('backup_name', '').strip()
        if not backup_name:
            return jsonify({'success': False, 'error': 'Backup name is required'})
        
        backup_path = os.path.join(os.path.dirname(ENV_FILE_PATH), backup_name)
        
        if not os.path.exists(backup_path) or not backup_name.startswith(os.path.basename(ENV_FILE_PATH) + '.backup'):
            return jsonify({'success': False, 'error': 'Invalid backup file'})
        
        # Create a backup of current file before restoring
        current_backup = f"{ENV_FILE_PATH}.backup.before_restore.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if os.path.exists(ENV_FILE_PATH):
            shutil.copy2(ENV_FILE_PATH, current_backup)
        
        # Restore the backup
        shutil.copy2(backup_path, ENV_FILE_PATH)
        logger.info(f"Restored from backup: {backup_name}")
        
        return jsonify({
            'success': True,
            'message': f'Restored from {backup_name}',
            'current_backup': os.path.basename(current_backup)
        })
    except Exception as e:
        logger.error(f"Error restoring backup: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/commands')
def commands():
    """Commands page"""
    try:
        # Get list of system users for dropdown
        result = subprocess.run(['cut', '-d:', '-f1', '/etc/passwd'], 
                              capture_output=True, text=True, timeout=10)
        all_users = result.stdout.strip().split('\n')
        # Filter to only show users with home directories
        system_users = []
        for user in all_users:
            home_dir = f'/home/{user}'
            if os.path.exists(home_dir):
                system_users.append(user)
    except Exception as e:
        logger.error(f"Error getting system users: {e}")
        system_users = []
    
    return render_template('commands.html', system_users=system_users)

@app.route('/disable-discord-auth', methods=['POST'])
@require_sudo()
def disable_discord_auth():
    """Disable Discord authentication"""
    try:
        script = f'''#!/bin/bash
echo "Disabling FORCE_DISCORD_AUTH in SnailyCAD..."
PGPASSWORD="{DB_PASSWORD}" psql -U postgres -d snaily-cad-v4 -h localhost <<EOF
UPDATE public."CadFeature" SET "isEnabled" = false WHERE feature = 'FORCE_DISCORD_AUTH';
SELECT feature, "isEnabled" FROM public."CadFeature" WHERE feature = 'FORCE_DISCORD_AUTH';
\\q
EOF
echo "✅ FORCE_DISCORD_AUTH has been disabled."'''
        
        result = subprocess.run(['bash', '-c', script], 
                              capture_output=True, text=True, timeout=30)
        
        logger.info("Discord auth disabled")
        return jsonify({
            'success': True,
            'output': result.stdout,
            'error': result.stderr
        })
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Command timed out'})
    except Exception as e:
        logger.error(f"Error disabling discord auth: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/unlink-discord', methods=['POST'])
def unlink_discord():
    """Unlink Discord ID"""
    try:
        discord_id = request.form.get('discord_id', '').strip()
        if not discord_id:
            return jsonify({'success': False, 'error': 'Discord ID is required'})
        
        # Validate Discord ID (should be numeric)
        if not discord_id.isdigit():
            return jsonify({'success': False, 'error': 'Invalid Discord ID format'})
        
        script = f'''#!/bin/bash
DB_NAME="snaily-cad-v4"
DB_USER="postgres"
DB_HOST="localhost"
PGPASSWORD="{DB_PASSWORD}" psql -U "$DB_USER" -d "$DB_NAME" -h "$DB_HOST" <<EOF
SELECT id, username, "discordId" FROM public."User" WHERE "discordId" = '{discord_id}';
UPDATE public."User" SET "discordId" = NULL WHERE "discordId" = '{discord_id}';
SELECT id, username, "discordId" FROM public."User" WHERE "discordId" IS NULL AND username IS NOT NULL;
\\q
EOF
echo "✅ Done. If the Discord ID existed, it has been unlinked."'''
        
        result = subprocess.run(['bash', '-c', script], 
                              capture_output=True, text=True, timeout=30)
        
        logger.info(f"Discord ID unlinked: {discord_id}")
        return jsonify({
            'success': True,
            'output': result.stdout,
            'error': result.stderr
        })
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Command timed out'})
    except Exception as e:
        logger.error(f"Error unlinking discord: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/create-user', methods=['POST'])
@require_sudo()
def create_user():
    """Create Ubuntu system user"""
    try:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password are required'})
        
        # Validate username
        if not re.match(r'^[a-z][a-z0-9_-]*$', username):
            return jsonify({'success': False, 'error': 'Invalid username format'})
        
        # Check if user already exists
        try:
            result = subprocess.run(['id', username], capture_output=True, text=True)
            if result.returncode == 0:
                return jsonify({'success': False, 'error': 'User already exists'})
        except:
            pass
        
        # Create user
        create_result = subprocess.run(['sudo', 'useradd', '-m', '-s', '/bin/bash', username], 
                                     capture_output=True, text=True, timeout=30)
        
        if create_result.returncode != 0:
            return jsonify({'success': False, 'error': f'Failed to create user: {create_result.stderr}'})
        
        # Set password
        passwd_process = subprocess.Popen(['sudo', 'passwd', username], 
                                        stdin=subprocess.PIPE, 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, 
                                        text=True)
        
        stdout, stderr = passwd_process.communicate(input=f'{password}\n{password}\n', timeout=30)
        
        if passwd_process.returncode != 0:
            # If password setting failed, remove the user
            subprocess.run(['sudo', 'userdel', '-r', username], capture_output=True, timeout=30)
            return jsonify({'success': False, 'error': f'Failed to set password: {stderr}'})
        
        logger.info(f"User created: {username}")
        return jsonify({
            'success': True,
            'output': f'User {username} created successfully'
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Command timed out'})
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete-user', methods=['POST'])
@require_sudo()
def delete_user():
    """Delete Ubuntu system user"""
    try:
        username = request.form.get('username', '').strip()
        
        if not username:
            return jsonify({'success': False, 'error': 'Username is required'})
        
        # Safety check - don't delete system users
        system_users = ['root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 
                       'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'list', 
                       'nobody', 'systemd-timesync', 'systemd-network', 'systemd-resolve',
                       'postgres', 'nginx']
        
        if username in system_users:
            return jsonify({'success': False, 'error': 'Cannot delete system users'})
        
        result = subprocess.run(['sudo', 'userdel', '-r', username], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            return jsonify({'success': False, 'error': f'Failed to delete user: {result.stderr}'})
        
        logger.info(f"User deleted: {username}")
        return jsonify({
            'success': True,
            'output': f'User {username} deleted successfully'
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Command timed out'})
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/reset-password', methods=['POST'])
@require_sudo()
def reset_password():
    """Reset Ubuntu user password"""
    try:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password are required'})
        
        # Set password
        passwd_process = subprocess.Popen(['sudo', 'passwd', username], 
                                        stdin=subprocess.PIPE, 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, 
                                        text=True)
        
        stdout, stderr = passwd_process.communicate(input=f'{password}\n{password}\n', timeout=30)
        
        if passwd_process.returncode != 0:
            return jsonify({'success': False, 'error': f'Failed to reset password: {stderr}'})
        
        logger.info(f"Password reset for user: {username}")
        return jsonify({
            'success': True,
            'output': f'Password reset successfully for user {username}'
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Command timed out'})
    except Exception as e:
        logger.error(f"Error resetting password: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/config-editor')
def config_editor():
    """Configuration file editor"""
    config_file_path = '/opt/snaily-admin/config.py'
    config_content = ""
    
    try:
        if os.path.exists(config_file_path):
            with open(config_file_path, 'r', encoding='utf-8') as f:
                config_content = f.read()
    except Exception as e:
        logger.error(f"Error reading config: {e}")
        flash(f'Error reading config file: {str(e)}', 'error')
    
    return render_template('config_editor.html', config_content=config_content)

@app.route('/save-config', methods=['POST'])
def save_config():
    """Save configuration file"""
    try:
        config_file_path = '/opt/snaily-admin/config.py'
        config_content = request.form.get('config_content', '')
        
        # Create backup
        if os.path.exists(config_file_path):
            backup_path = f"{config_file_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(config_file_path, backup_path)
        
        # Write new config
        with open(config_file_path, 'w', encoding='utf-8') as f:
            f.write(config_content)
        
        logger.info("Configuration file updated")
        return jsonify({'success': True, 'message': 'Configuration saved successfully! Restart the admin panel to apply changes.'})
    except Exception as e:
        logger.error(f"Error saving config: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/test-config', methods=['POST'])
def test_config():
    """Test configuration syntax"""
    try:
        config_content = request.form.get('config_content', '')
        
        # Create temporary file to test syntax
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
            temp_file.write(config_content)
            temp_file_path = temp_file.name
        
        # Try to compile the Python code
        try:
            with open(temp_file_path, 'r', encoding='utf-8') as f:
                compile(f.read(), temp_file_path, 'exec')
            
            # Try to import and check required variables
            spec = importlib.util.spec_from_file_location("test_config", temp_file_path)
            test_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(test_module)
            
            # Check for required variables
            required_vars = ['WHITELISTED_IPS', 'DB_PASSWORD']
            missing_vars = []
            for var in required_vars:
                if not hasattr(test_module, var):
                    missing_vars.append(var)
            
            if missing_vars:
                return jsonify({
                    'success': False,
                    'error': f'Missing required variables: {", ".join(missing_vars)}'
                })
            
            # Check WHITELISTED_IPS format
            if not isinstance(test_module.WHITELISTED_IPS, list):
                return jsonify({
                    'success': False,
                    'error': 'WHITELISTED_IPS must be a list'
                })
            
            # Check DB_PASSWORD format
            if not isinstance(test_module.DB_PASSWORD, str):
                return jsonify({
                    'success': False,
                    'error': 'DB_PASSWORD must be a string'
                })
            
            return jsonify({
                'success': True,
                'message': 'Configuration syntax is valid!'
            })
            
        except SyntaxError as e:
            return jsonify({
                'success': False,
                'error': f'Syntax error: {str(e)}'
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Configuration error: {str(e)}'
            })
        finally:
            # Clean up temporary file
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
            
    except Exception as e:
        logger.error(f"Error testing config: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/restart-admin', methods=['POST'])
@require_sudo()
def restart_admin():
    """Restart the admin panel service"""
    try:
        # Try to restart the systemd service
        result = subprocess.run(['sudo', 'systemctl', 'restart', 'snaily-admin'], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            logger.info("Admin panel service restarted")
            return jsonify({
                'success': True,
                'output': 'Admin panel service restart initiated. Please refresh the page in a few seconds.'
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Failed to restart service: {result.stderr}'
            })
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Restart command timed out'})
    except Exception as e:
        logger.error(f"Error restarting admin: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/backup-manager')
def backup_manager():
    """Backup management page"""
    return render_template('backup_manager.html')

@app.route('/nginx-editor')
def nginx_editor():
    """Nginx configuration editor"""
    try:
        if os.path.exists(NGINX_CONF_PATH):
            with open(NGINX_CONF_PATH, 'r', encoding='utf-8') as f:
                nginx_content = f.read()
        else:
            nginx_content = """# Nginx Configuration
# Basic configuration template

user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 768;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Virtual Host Configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
"""
        
        # Get file metadata
        file_stats = os.stat(NGINX_CONF_PATH) if os.path.exists(NGINX_CONF_PATH) else None
        last_modified = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S') if file_stats else 'File not found'
        
        return render_template('nginx_editor.html', 
                             nginx_content=nginx_content, 
                             last_modified=last_modified,
                             file_path=NGINX_CONF_PATH)
    except Exception as e:
        logger.error(f"Error in nginx editor: {e}")
        flash(f'Error reading nginx.conf file: {str(e)}', 'error')
        return render_template('nginx_editor.html', nginx_content='', last_modified='Error', file_path=NGINX_CONF_PATH)

@app.route('/save-nginx', methods=['POST'])
@require_sudo()
def save_nginx():
    """Save nginx configuration file"""
    try:
        nginx_content = request.form.get('nginx_content', '')
        
        # Create backup with timestamp
        if os.path.exists(NGINX_CONF_PATH):
            backup_path = f"{NGINX_CONF_PATH}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(NGINX_CONF_PATH, backup_path)
        
        # Write the content directly
        with open(NGINX_CONF_PATH, 'w', encoding='utf-8') as f:
            f.write(nginx_content)
        
        # Get updated file info
        file_stats = os.stat(NGINX_CONF_PATH)
        last_modified = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        
        logger.info("Nginx configuration updated")
        return jsonify({
            'success': True,
            'message': 'Nginx configuration saved successfully!',
            'last_modified': last_modified
        })
    except Exception as e:
        logger.error(f"Error saving nginx config: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/validate-nginx', methods=['POST'])
def validate_nginx():
    """Validate nginx configuration syntax"""
    try:
        nginx_content = request.form.get('nginx_content', '')
        
        # Write content to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp_file:
            temp_file.write(nginx_content)
            temp_file_path = temp_file.name
        
        try:
            # Test nginx configuration syntax
            result = subprocess.run(['nginx', '-t', '-c', temp_file_path], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return jsonify({
                    'success': True,
                    'is_valid': True,
                    'message': 'Nginx configuration syntax is valid',
                    'output': result.stderr  # nginx -t outputs to stderr even on success
                })
            else:
                return jsonify({
                    'success': True,
                    'is_valid': False,
                    'message': 'Nginx configuration has syntax errors',
                    'errors': [result.stderr]
                })
                
        except subprocess.TimeoutExpired:
            return jsonify({
                'success': False,
                'error': 'Nginx validation timed out'
            })
        except FileNotFoundError:
            return jsonify({
                'success': False,
                'error': 'Nginx binary not found. Please ensure nginx is installed.'
            })
        finally:
            # Clean up temporary file
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
                
    except Exception as e:
        logger.error(f"Error validating nginx: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/reload-nginx', methods=['POST'])
@require_sudo()
def reload_nginx():
    """Reload nginx configuration"""
    try:
        # First test the configuration
        test_result = subprocess.run(['nginx', '-t'], capture_output=True, text=True, timeout=10)
        
        if test_result.returncode != 0:
            return jsonify({
                'success': False,
                'error': f'Nginx configuration test failed: {test_result.stderr}'
            })
        
        # Reload nginx
        reload_result = subprocess.run(['sudo', 'systemctl', 'reload', 'nginx'], 
                                     capture_output=True, text=True, timeout=30)
        
        if reload_result.returncode == 0:
            logger.info("Nginx configuration reloaded")
            return jsonify({
                'success': True,
                'message': 'Nginx configuration reloaded successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Failed to reload nginx: {reload_result.stderr}'
            })
            
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Command timed out'})
    except Exception as e:
        logger.error(f"Error reloading nginx: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/restart-nginx', methods=['POST'])
@require_sudo()
def restart_nginx():
    """Restart nginx service"""
    try:
        # First test the configuration
        test_result = subprocess.run(['nginx', '-t'], capture_output=True, text=True, timeout=10)
        
        if test_result.returncode != 0:
            return jsonify({
                'success': False,
                'error': f'Nginx configuration test failed: {test_result.stderr}'
            })
        
        # Restart nginx
        restart_result = subprocess.run(['sudo', 'systemctl', 'restart', 'nginx'], 
                                      capture_output=True, text=True, timeout=30)
        
        if restart_result.returncode == 0:
            logger.info("Nginx service restarted")
            return jsonify({
                'success': True,
                'message': 'Nginx service restarted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Failed to restart nginx: {restart_result.stderr}'
            })
            
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Command timed out'})
    except Exception as e:
        logger.error(f"Error restarting nginx: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/nginx-status', methods=['GET'])
def nginx_status():
    """Check nginx service status"""
    try:
        # Check if nginx is active
        status_result = subprocess.run(['systemctl', 'is-active', 'nginx'], 
                                     capture_output=True, text=True, timeout=10)
        is_active = status_result.stdout.strip() == 'active'
        
        # Get nginx version
        version_result = subprocess.run(['nginx', '-v'], 
                                      capture_output=True, text=True, timeout=10)
        version = version_result.stderr.strip() if version_result.returncode == 0 else 'Unknown'
        
        # Test configuration
        test_result = subprocess.run(['nginx', '-t'], capture_output=True, text=True, timeout=10)
        config_valid = test_result.returncode == 0
        
        return jsonify({
            'success': True,
            'is_active': is_active,
            'version': version,
            'config_valid': config_valid,
            'test_output': test_result.stderr
        })
        
    except Exception as e:
        logger.error(f"Error getting nginx status: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/status')
def status():
    """SnailyCAD system status check"""
    try:
        # Check if SnailyCAD directory exists and is accessible
        snailycad_status = os.path.exists('/home/snaily-cadv4') and os.access('/home/snaily-cadv4', os.R_OK)
        
        # Check if .env file exists
        env_status = os.path.exists(ENV_FILE_PATH)
        
        # Check PostgreSQL status
        try:
            postgres_result = subprocess.run(['systemctl', 'is-active', 'postgresql'], 
                                           capture_output=True, text=True, timeout=10)
            postgres_status = postgres_result.stdout.strip() == 'active'
        except:
            postgres_status = False
        
        # Check Nginx status
        try:
            nginx_result = subprocess.run(['systemctl', 'is-active', 'nginx'], 
                                        capture_output=True, text=True, timeout=10)
            nginx_status = nginx_result.stdout.strip() == 'active'
        except:
            nginx_status = False
        
        # Test database connection
        db_connection = False
        try:
            result = subprocess.run([
                'psql', '-h', 'localhost', '-U', 'postgres', '-d', 'snaily-cad-v4', '-c', 'SELECT 1;'
            ], env={'PGPASSWORD': DB_PASSWORD}, capture_output=True, text=True, timeout=10)
            db_connection = result.returncode == 0
        except:
            pass
        
        # Check disk space
        disk_usage = {}
        try:
            disk_result = subprocess.run(['df', '-h', '/home/snaily-cadv4'], 
                                       capture_output=True, text=True, timeout=10)
            if disk_result.returncode == 0:
                lines = disk_result.stdout.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) >= 5:
                        disk_usage = {
                            'filesystem': parts[0],
                            'size': parts[1],
                            'used': parts[2],
                            'available': parts[3],
                            'use_percent': parts[4]
                        }
        except:
            pass
        
        # System information
        try:
            uptime_result = subprocess.run(['uptime', '-p'], capture_output=True, text=True, timeout=5)
            uptime = uptime_result.stdout.strip() if uptime_result.returncode == 0 else 'Unknown'
        except:
            uptime = 'Unknown'
        
        return render_template('status.html', 
                             snailycad_directory=snailycad_status,
                             env_file=env_status,
                             postgresql=postgres_status,
                             nginx_service=nginx_status,
                             database_connection=db_connection,
                             disk_usage=disk_usage,
                             uptime=uptime,
                             overall_status=all([snailycad_status, env_status, postgres_status, db_connection]))
    except Exception as e:
        logger.error(f"Error in status check: {e}")
        return render_template('status.html', error=str(e))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('/var/log/snaily-admin', exist_ok=True)
    
    # Run the application
    app.run(host='0.0.0.0', port=5000, debug=False)
