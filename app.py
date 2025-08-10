from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
import subprocess
import shutil
from datetime import datetime
import re
from config import WHITELISTED_IPS, DB_PASSWORD

app = Flask(__name__)
app.secret_key = 'snailycad-secret-key-change-this'

ENV_FILE_PATH = '/home/snaily-cadv4/.env'

def check_ip():
    """Check if the request IP is whitelisted"""
    client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    if client_ip not in WHITELISTED_IPS:
        return False
    return True

@app.before_request
def before_request():
    """Check IP whitelist before each request"""
    if not check_ip():
        return redirect('https://acd.swiftpeakhosting.com/')

def parse_env_file(file_path):
    """Parse .env file into key-value pairs"""
    env_vars = {}
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        env_vars[key.strip()] = value.strip()
    return env_vars

def write_env_file(file_path, env_vars):
    """Write environment variables back to .env file"""
    # Create backup
    if os.path.exists(file_path):
        backup_path = f"{file_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(file_path, backup_path)
    
    with open(file_path, 'w') as f:
        for key, value in env_vars.items():
            f.write(f"{key}={value}\n")

@app.route('/')
def editor():
    """Main .env editor page"""
    env_vars = parse_env_file(ENV_FILE_PATH)
    return render_template('editor.html', env_vars=env_vars)

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
        
        write_env_file(ENV_FILE_PATH, env_vars)
        flash('SnailyCAD environment file saved successfully!', 'success')
    except Exception as e:
        flash(f'Error saving file: {str(e)}', 'error')
    
    return redirect(url_for('editor'))

@app.route('/commands')
def commands():
    """Commands page"""
    # Get list of system users for dropdown
    try:
        result = subprocess.run(['cut', '-d:', '-f1', '/etc/passwd'], 
                              capture_output=True, text=True)
        all_users = result.stdout.strip().split('\n')
        # Filter to only show users with home directories
        system_users = []
        for user in all_users:
            home_dir = f'/home/{user}'
            if os.path.exists(home_dir):
                system_users.append(user)
    except:
        system_users = []
    
    return render_template('commands.html', system_users=system_users)

@app.route('/disable-discord-auth', methods=['POST'])
def disable_discord_auth():
    """Disable Discord authentication"""
    try:
        script = '''#!/bin/bash
echo "Disabling FORCE_DISCORD_AUTH in SnailyCAD..."
sudo -i -u postgres psql snaily-cad-v4 <<EOF
UPDATE public."CadFeature" SET "isEnabled" = false WHERE feature = 'FORCE_DISCORD_AUTH';
SELECT feature, "isEnabled" FROM public."CadFeature" WHERE feature = 'FORCE_DISCORD_AUTH';
EOF
echo "✅ FORCE_DISCORD_AUTH has been disabled."'''
        
        result = subprocess.run(['bash', '-c', script], 
                              capture_output=True, text=True, timeout=30)
        
        return jsonify({
            'success': True,
            'output': result.stdout,
            'error': result.stderr
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

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
EOF
echo "✅ Done. If the Discord ID existed, it has been unlinked."'''
        
        result = subprocess.run(['bash', '-c', script], 
                              capture_output=True, text=True, timeout=30)
        
        return jsonify({
            'success': True,
            'output': result.stdout,
            'error': result.stderr
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/create-user', methods=['POST'])
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
        
        # Create user
        create_result = subprocess.run(['sudo', 'useradd', '-m', '-s', '/bin/bash', username], 
                                     capture_output=True, text=True)
        
        if create_result.returncode != 0:
            return jsonify({'success': False, 'error': f'Failed to create user: {create_result.stderr}'})
        
        # Set password
        passwd_process = subprocess.Popen(['sudo', 'passwd', username], 
                                        stdin=subprocess.PIPE, 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, 
                                        text=True)
        
        stdout, stderr = passwd_process.communicate(input=f'{password}\n{password}\n')
        
        if passwd_process.returncode != 0:
            # If password setting failed, remove the user
            subprocess.run(['sudo', 'userdel', '-r', username], capture_output=True)
            return jsonify({'success': False, 'error': f'Failed to set password: {stderr}'})
        
        return jsonify({
            'success': True,
            'output': f'User {username} created successfully'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/delete-user', methods=['POST'])
def delete_user():
    """Delete Ubuntu system user"""
    try:
        username = request.form.get('username', '').strip()
        
        if not username:
            return jsonify({'success': False, 'error': 'Username is required'})
        
        # Safety check - don't delete system users
        system_users = ['root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 
                       'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'list', 
                       'nobody', 'systemd-timesync', 'systemd-network', 'systemd-resolve']
        
        if username in system_users:
            return jsonify({'success': False, 'error': 'Cannot delete system users'})
        
        result = subprocess.run(['sudo', 'userdel', '-r', username], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            return jsonify({'success': False, 'error': f'Failed to delete user: {result.stderr}'})
        
        return jsonify({
            'success': True,
            'output': f'User {username} deleted successfully'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/reset-password', methods=['POST'])
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
        
        stdout, stderr = passwd_process.communicate(input=f'{password}\n{password}\n')
        
        if passwd_process.returncode != 0:
            return jsonify({'success': False, 'error': f'Failed to reset password: {stderr}'})
        
        return jsonify({
            'success': True,
            'output': f'Password reset successfully for user {username}'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/config-editor')
def config_editor():
    """Configuration file editor"""
    config_file_path = '/opt/snaily-admin/config.py'
    config_content = ""
    
    try:
        if os.path.exists(config_file_path):
            with open(config_file_path, 'r') as f:
                config_content = f.read()
    except Exception as e:
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
        with open(config_file_path, 'w') as f:
            f.write(config_content)
        
        return jsonify({'success': True, 'message': 'Configuration saved successfully! Restart the admin panel to apply changes.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/test-config', methods=['POST'])
def test_config():
    """Test configuration syntax"""
    try:
        config_content = request.form.get('config_content', '')
        
        # Create temporary file to test syntax
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
            temp_file.write(config_content)
            temp_file_path = temp_file.name
        
        # Try to compile the Python code
        try:
            with open(temp_file_path, 'r') as f:
                compile(f.read(), temp_file_path, 'exec')
            
            # Try to import and check required variables
            import importlib.util
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
            os.unlink(temp_file_path)
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/restart-admin', methods=['POST'])
def restart_admin():
    """Restart the admin panel service"""
    try:
        # Try to restart the systemd service
        result = subprocess.run(['sudo', 'systemctl', 'restart', 'snaily-admin'], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            return jsonify({
                'success': True,
                'output': 'Admin panel service restart initiated. Please refresh the page in a few seconds.'
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Failed to restart service: {result.stderr}'
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/status')
def status():
    """SnailyCAD system status check"""
    try:
        # Check if SnailyCAD directory exists and is accessible
        snailycad_status = os.path.exists('/home/snaily-cadv4') and os.access('/home/snaily-cadv4', os.R_OK)
        
        # Check if .env file exists
        env_status = os.path.exists(ENV_FILE_PATH)
        
        # Check PostgreSQL status
        postgres_status = subprocess.run(['systemctl', 'is-active', 'postgresql'], 
                                       capture_output=True, text=True).stdout.strip() == 'active'
        
        # Test database connection
        db_connection = False
        try:
            result = subprocess.run([
                'psql', '-h', 'localhost', '-U', 'postgres', '-d', 'snaily-cad-v4', '-c', 'SELECT 1;'
            ], env={'PGPASSWORD': DB_PASSWORD}, capture_output=True, text=True, timeout=10)
            db_connection = result.returncode == 0
        except:
            pass
        
        return jsonify({
            'snailycad_directory': snailycad_status,
            'env_file': env_status,
            'postgresql': postgres_status,
            'database_connection': db_connection,
            'overall_status': all([snailycad_status, env_status, postgres_status, db_connection])
        })
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
