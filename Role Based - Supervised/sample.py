import requests
import pandas as pd
import logging
from datetime import datetime
from requests.auth import HTTPBasicAuth

# Configure logging
def setup_logging(document_key):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"servicenow_audit_{document_key}_{timestamp}.log"
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )
    return log_filename

# Helper function to log and print
def log_print(message):
    print(message)
    logging.info(message)

class ServiceNowAuditAnalyzer:
    def __init__(self, instance_url, username, password):
        """
        Initialize ServiceNow connection
        
        Args:
            instance_url: Your ServiceNow instance URL (e.g., 'https://dev280836.service-now.com')
            username: ServiceNow username
            password: ServiceNow password
        """
        self.instance_url = instance_url.rstrip('/')
        self.auth = HTTPBasicAuth(username, password)
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    
    def make_api_call(self, endpoint, params=None):
        """Make API call to ServiceNow with error handling"""
        url = f"{self.instance_url}/api/now/table/{endpoint}"
        
        try:
            response = requests.get(url, auth=self.auth, headers=self.headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            log_print(f"API call failed: {e}")
            return None
    
    def get_audit_records(self, document_key):
        """Get audit records for a specific CI"""
        log_print(f"Fetching audit records for CI: {document_key}")
        
        params = {
            'sysparm_query': f'documentkey={document_key}',
            'sysparm_fields': 'sys_created_on,fieldname,oldvalue,newvalue,user',
            'sysparm_limit': 1000,
            'sysparm_order_by': 'sys_created_on'
        }
        
        result = self.make_api_call('sys_audit', params=params)
        
        if not result or not result.get('result'):
            log_print("No audit records found")
            return []
        
        audit_records = result['result']
        log_print(f"Found {len(audit_records)} audit records")
        return audit_records
    
    def get_user_details(self, user_sys_id):
        """Get user details from sys_user table"""
        params = {
            'sysparm_query': f'sys_id={user_sys_id}',
            'sysparm_fields': 'sys_id,user_name,first_name,last_name,email'
        }
        
        result = self.make_api_call('sys_user', params=params)
        
        if result and result.get('result') and len(result['result']) > 0:
            user = result['result'][0]
            full_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
            if not full_name:
                full_name = user.get('user_name', 'Unknown User')
            
            return {
                'sys_id': user.get('sys_id'),
                'user_name': user.get('user_name', 'Unknown'),
                'full_name': full_name,
                'email': user.get('email', '')
            }
        return None
    
    def get_user_roles(self, user_sys_id):
        """Get roles for a specific user from sys_user_has_role table"""
        log_print(f"    Fetching roles for user: {user_sys_id}")
        
        params = {
            'sysparm_query': f'user={user_sys_id}',
            'sysparm_fields': 'role,role.name,granted_by',
            'sysparm_display_value': 'true'  # This will resolve reference fields to display values
        }
        
        result = self.make_api_call('sys_user_has_role', params=params)
        
        if not result or not result.get('result'):
            log_print(f"    No roles found for user {user_sys_id}")
            return []
        
        log_print(f"    Found {len(result['result'])} role assignments")
        
        # Extract role names from the results
        role_names = []
        for role_record in result['result']:
            # Try different ways to get the role name
            role_name = None
            
            # Method 1: Direct role.name field (with display_value=true)
            if 'role.name' in role_record:
                role_name = role_record['role.name']
            
            # Method 2: Check if role field contains the name directly
            elif 'role' in role_record and isinstance(role_record['role'], str):
                role_name = role_record['role']
            
            # Method 3: If role is a dict with display_value
            elif 'role' in role_record and isinstance(role_record['role'], dict):
                if 'display_value' in role_record['role']:
                    role_name = role_record['role']['display_value']
                elif 'value' in role_record['role']:
                    # If we have sys_id, make separate call to get name
                    role_sys_id = role_record['role']['value']
                    role_details = self.get_role_details(role_sys_id)
                    if role_details:
                        role_name = role_details['name']
            
            if role_name and role_name not in role_names:
                role_names.append(role_name)
                log_print(f"      Role found: {role_name}")
        
        log_print(f"    Total unique roles: {len(role_names)}")
        return role_names
    
    def get_role_details(self, role_sys_id):
        """Get role details from sys_user_role table"""
        params = {
            'sysparm_query': f'sys_id={role_sys_id}',
            'sysparm_fields': 'sys_id,name,description'
        }
        
        result = self.make_api_call('sys_user_role', params=params)
        
        if result and result.get('result') and len(result['result']) > 0:
            role = result['result'][0]
            return {
                'sys_id': role.get('sys_id'),
                'name': role.get('name', 'Unknown Role'),
                'description': role.get('description', '')
            }
        return None
    
    def analyze_ci_audit_records(self, document_key):
        """Main method to analyze CI audit records with user details and roles"""
        log_print("="*80)
        log_print("CI AUDIT ANALYSIS WITH USER ROLES")
        log_print("="*80)
        
        # Step 1: Get audit records
        audit_records = self.get_audit_records(document_key)
        if not audit_records:
            return
        
        # Step 2: Process each audit record
        user_activities = {}
        
        log_print("\nProcessing audit records and fetching user details...\n")
        
        for i, record in enumerate(audit_records, 1):
            user_sys_id = record.get('user')
            
            if not user_sys_id:
                continue
            
            # Get user details if not already cached
            if user_sys_id not in user_activities:
                log_print(f"Processing user {i}/{len(audit_records)}: {user_sys_id}")
                
                user_details = self.get_user_details(user_sys_id)
                if not user_details:
                    log_print(f"  ❌ Could not get user details for {user_sys_id}")
                    continue
                
                log_print(f"  ✅ User: {user_details['full_name']} ({user_details['user_name']})")
                user_roles = self.get_user_roles(user_sys_id)
                
                user_activities[user_sys_id] = {
                    'user_details': user_details,
                    'roles': user_roles,
                    'changes': []
                }
            
            # Add change record
            change_info = {
                'created': record.get('sys_created_on'),
                'field': record.get('fieldname'),
                'old_value': record.get('oldvalue'),
                'new_value': record.get('newvalue')
            }
            
            user_activities[user_sys_id]['changes'].append(change_info)
        
        # Step 3: Display results
        log_print("\n" + "="*80)
        log_print("USER ACTIVITIES SUMMARY")
        log_print("="*80)
        
        # Sort users by number of changes (most active first)
        sorted_users = sorted(user_activities.items(), 
                            key=lambda x: len(x[1]['changes']), 
                            reverse=True)
        
        total_users = len(sorted_users)
        total_changes = sum(len(user_data['changes']) for _, user_data in sorted_users)
        
        log_print(f"📊 Total Users: {total_users}")
        log_print(f"📊 Total Changes: {total_changes}")
        log_print(f"📊 CI: {document_key}")
        
        log_print("\n" + "="*80)
        log_print("DETAILED USER ACTIVITY")
        log_print("="*80)
        
        for user_sys_id, user_data in sorted_users:
            user_details = user_data['user_details']
            roles = user_data['roles']
            changes = user_data['changes']
            
            log_print(f"\n👤 Name: {user_details['full_name']}")
            log_print(f"   Username: {user_details['user_name']}")
            log_print(f"   Email: {user_details['email']}")
            log_print(f"   Roles: {', '.join(roles) if roles else 'No roles assigned'}")
            log_print(f"   Total Changes: {len(changes)}")
            log_print(f"   Changes Made:")
            
            # Group changes by field for better readability
            changes_by_field = {}
            for change in changes:
                field = change['field']
                if field not in changes_by_field:
                    changes_by_field[field] = []
                changes_by_field[field].append(change)
            
            for field, field_changes in changes_by_field.items():
                log_print(f"      📝 {field}:")
                for change in field_changes:
                    old_val = change['old_value'] or '[empty]'
                    new_val = change['new_value'] or '[empty]'
                    log_print(f"         • Changed from '{old_val}' to '{new_val}' on {change['created']}")
            
            log_print(f"   {'-'*60}")
        
        # Step 4: Summary statistics
        log_print(f"\n" + "="*80)
        log_print("OWNERSHIP ANALYSIS")
        log_print("="*80)
        
        # Analyze ownership indicators
        ownership_candidates = []
        
        for user_sys_id, user_data in sorted_users:
            user_details = user_data['user_details']
            roles = user_data['roles']
            changes = user_data['changes']
            
            # Calculate ownership score
            total_changes = len(changes)
            unique_fields = len(set(change['field'] for change in changes))
            
            # Check for critical field changes
            critical_fields = ['install_status', 'environment', 'assigned_to', 'assigned']
            critical_changes = sum(1 for change in changes if change['field'] in critical_fields)
            
            # Check for admin privileges
            has_admin_role = any('admin' in role.lower() for role in roles)
            has_cmdb_role = any('cmdb' in role.lower() for role in roles)
            
            ownership_score = (
                total_changes * 0.3 +
                unique_fields * 0.2 +
                critical_changes * 0.3 +
                (10 if has_admin_role else 0) * 0.1 +
                (10 if has_cmdb_role else 0) * 0.1
            )
            
            ownership_candidates.append({
                'name': user_details['full_name'],
                'username': user_details['user_name'],
                'roles': roles,
                'total_changes': total_changes,
                'unique_fields': unique_fields,
                'critical_changes': critical_changes,
                'ownership_score': round(ownership_score, 2)
            })
        
        # Sort by ownership score
        ownership_candidates.sort(key=lambda x: x['ownership_score'], reverse=True)
        
        log_print(f"🏆 TOP OWNERSHIP CANDIDATES:")
        for i, candidate in enumerate(ownership_candidates[:5], 1):
            log_print(f"   {i}. {candidate['name']} ({candidate['username']})")
            log_print(f"      Roles: {', '.join(candidate['roles']) if candidate['roles'] else 'No roles'}")
            log_print(f"      Activity: {candidate['total_changes']} changes, {candidate['unique_fields']} fields, {candidate['critical_changes']} critical")
            log_print(f"      Ownership Score: {candidate['ownership_score']}")
            log_print("")
        
        return {
            'user_activities': user_activities,
            'ownership_candidates': ownership_candidates,
            'summary': {
                'total_users': total_users,
                'total_changes': total_changes,
                'ci_id': document_key
            }
        }


# Usage Example
if __name__ == "__main__":
    # Configuration
    INSTANCE_URL = "https://dev280836.service-now.com"
    USERNAME = "admin"
    PASSWORD = "Infinitywar1@"
    
    # Target CI
    DOCUMENT_KEY = "b4fd7c8437201000deeabfc8bcbe5dc1"
    
    # Initialize the analyzer
    analyzer = ServiceNowAuditAnalyzer(INSTANCE_URL, USERNAME, PASSWORD)
    
    # Setup logging
    log_filename = setup_logging(DOCUMENT_KEY)
    log_print(f"Logging output to: {log_filename}")
    
    try:
        # Analyze CI audit records
        log_print("\n" + "="*80)
        log_print("STARTING MAIN ANALYSIS")
        log_print("="*80)
        
        results = analyzer.analyze_ci_audit_records(DOCUMENT_KEY)
        
        if results:
            log_print("\n" + "="*80)
            log_print("ANALYSIS COMPLETED SUCCESSFULLY!")
            log_print("="*80)
            log_print(f"✅ Processed {results['summary']['total_users']} users")
            log_print(f"✅ Analyzed {results['summary']['total_changes']} audit records")
            log_print("✅ Identified top ownership candidates")
        else:
            log_print("❌ Failed to analyze audit records")
    
    except Exception as e:
        log_print(f"❌ Error: {e}")
        log_print("Please verify your ServiceNow credentials and instance URL.")