import requests
import logging
from datetime import datetime
from requests.auth import HTTPBasicAuth
import sys
import traceback
import os

class CMDBOwnershipAnalyzer:
    def __init__(self, instance_url, username, password):
        """
        Initialize ServiceNow connection
        
        Args:
            instance_url: ServiceNow instance URL
            username: ServiceNow username
            password: ServiceNow password
        """
        try:
            self.instance_url = instance_url.rstrip('/')
            self.auth = HTTPBasicAuth(username, password)
            self.headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # Define role configurations for different CI types
            self.role_configs = {
                'cmdb_ci_server': {  # For servers
                    'critical_roles': [
                        'admin',
                        'cmdb_admin',
                        'server_admin',
                        'infrastructure_admin',
                        'system_admin',
                        'platform_admin'
                    ],
                    'role_weights': {
                        'admin': 15,
                        'server_admin': 20,
                        'infrastructure_admin': 18,
                        'system_admin': 15,
                        'platform_admin': 15,
                        'cmdb_admin': 12
                    }
                },
                'cmdb_ci_database': {  # For databases
                    'critical_roles': [
                        'admin',
                        'cmdb_admin',
                        'database_admin',
                        'dba',
                        'db_owner',
                        'data_admin'
                    ],
                    'role_weights': {
                        'admin': 15,
                        'database_admin': 20,
                        'dba': 20,
                        'db_owner': 18,
                        'data_admin': 15,
                        'cmdb_admin': 12
                    }
                },
                'cmdb_ci_app_server': {  # For application servers
                    'critical_roles': [
                        'admin',
                        'cmdb_admin',
                        'app_admin',
                        'application_owner',
                        'app_support',
                        'middleware_admin'
                    ],
                    'role_weights': {
                        'admin': 15,
                        'app_admin': 20,
                        'application_owner': 18,
                        'app_support': 15,
                        'middleware_admin': 15,
                        'cmdb_admin': 12
                    }
                },
                'cmdb_ci_network_device': {  # For network devices
                    'critical_roles': [
                        'admin',
                        'cmdb_admin',
                        'network_admin',
                        'network_engineer',
                        'infrastructure_admin',
                        'security_admin'
                    ],
                    'role_weights': {
                        'admin': 15,
                        'network_admin': 20,
                        'network_engineer': 18,
                        'infrastructure_admin': 15,
                        'security_admin': 15,
                        'cmdb_admin': 12
                    }
                },
                'default': {  # Default configuration for unknown CI types
                    'critical_roles': [
                        'admin',
                        'cmdb_admin',
                        'asset_manager',
                        'configuration_admin'
                    ],
                    'role_weights': {
                        'admin': 15,
                        'cmdb_admin': 15,
                        'asset_manager': 12,
                        'configuration_admin': 12
                    }
                }
            }
            
            # Define critical fields based on CI type
            self.field_configs = {
                'cmdb_ci_server': {  # For servers
                    'critical_fields': {
                        'assigned_to': 15,           # Very high - direct ownership
                        'managed_by': 15,            # Very high - operational ownership
                        'supported_by': 12,          # High - support ownership
                        'install_status': 10,        # High - lifecycle management
                        'os': 8,                     # Medium - OS management
                        'os_version': 8,             # Medium - OS management
                        'ip_address': 6,             # Medium - network configuration
                        'ram': 5,                    # Low - hardware management
                        'cpu_count': 5,              # Low - hardware management
                        'disk_space': 5              # Low - hardware management
                    }
                },
                'cmdb_ci_database': {  # For databases
                    'critical_fields': {
                        'assigned_to': 15,           # Very high - direct ownership
                        'managed_by': 15,            # Very high - operational ownership
                        'supported_by': 12,          # High - support ownership
                        'install_status': 10,        # High - lifecycle management
                        'database_version': 10,      # High - version management
                        'instance_name': 8,          # Medium - instance management
                        'port': 6,                   # Medium - connectivity
                        'backup_schedule': 8,        # Medium - backup management
                        'replication_status': 8,     # Medium - replication management
                        'maintenance_schedule': 8    # Medium - maintenance management
                    }
                },
                'cmdb_ci_app_server': {  # For application servers
                    'critical_fields': {
                        'assigned_to': 15,           # Very high - direct ownership
                        'managed_by': 15,            # Very high - operational ownership
                        'supported_by': 12,          # High - support ownership
                        'install_status': 10,        # High - lifecycle management
                        'application_version': 10,   # High - version management
                        'deployment_status': 8,      # Medium - deployment management
                        'environment': 8,            # Medium - environment context
                        'port': 6,                   # Medium - connectivity
                        'middleware_type': 6,        # Medium - middleware management
                        'deployment_path': 6         # Medium - deployment configuration
                    }
                },
                'cmdb_ci_network_device': {  # For network devices
                    'critical_fields': {
                        'assigned_to': 15,           # Very high - direct ownership
                        'managed_by': 15,            # Very high - operational ownership
                        'supported_by': 12,          # High - support ownership
                        'install_status': 10,        # High - lifecycle management
                        'ip_address': 10,            # High - network configuration
                        'subnet_mask': 8,            # Medium - network configuration
                        'gateway': 8,                # Medium - network configuration
                        'firmware_version': 8,       # Medium - firmware management
                        'vlan': 6,                   # Medium - VLAN configuration
                        'configuration': 6           # Medium - device configuration
                    }
                },
                'default': {  # Default configuration for unknown CI types
                    'critical_fields': {
                        'assigned_to': 15,           # Very high - direct ownership
                        'managed_by': 15,            # Very high - operational ownership
                        'supported_by': 12,          # High - support ownership
                        'install_status': 10,        # High - lifecycle management
                        'environment': 8,            # Medium - environment context
                        'category': 6,               # Medium - categorization
                        'subcategory': 6,            # Medium - categorization
                        'operational_status': 8,     # Medium - operational status
                        'maintenance_schedule': 6,    # Medium - maintenance
                        'comments': 4                # Low - documentation
                    }
                }
            }
            
            # Setup logging first
            self._setup_logging()
            
            logging.info("="*80)
            logging.info("Initializing CMDBOwnershipAnalyzer")
            logging.info(f"Instance URL: {instance_url}")
            logging.info(f"Username: {username}")
            logging.info("="*80)
            
        except Exception as e:
            print(f"Error during initialization: {str(e)}")
            traceback.print_exc()
            raise

    def _setup_logging(self):
        """Configure logging"""
        try:
            # Create logs directory if it doesn't exist
            if not os.path.exists('logs'):
                os.makedirs('logs')
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_filename = f"logs/cmdb_ownership_analysis_{timestamp}.txt"
            
            # Configure file handler for essential logging only
            file_handler = logging.FileHandler(log_filename)
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(logging.Formatter('%(message)s'))
            
            # Setup root logger
            root_logger = logging.getLogger()
            root_logger.setLevel(logging.INFO)
            root_logger.addHandler(file_handler)
            
            print(f"Analysis results will be written to: {log_filename}")
            
        except Exception as e:
            print(f"Error setting up logging: {str(e)}")
            raise

    def make_api_call(self, endpoint, params=None):
        """Make API call to ServiceNow with minimal error handling"""
        try:
            url = f"{self.instance_url}/api/now/table/{endpoint}"
            response = requests.get(url, auth=self.auth, headers=self.headers, params=params)
            
            if response.status_code != 200:
                print(f"API call failed: {response.status_code}")
                return None
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"API call failed: {str(e)}")
            return None

    def get_audit_records(self, document_key):
        """Get audit records for a specific CI"""
        logging.info(f"Fetching audit records for CI: {document_key}")
        
        params = {
            'sysparm_query': f'documentkey={document_key}',
            'sysparm_fields': 'sys_created_on,fieldname,oldvalue,newvalue,user,update_count',
            'sysparm_limit': 1000
        }
        
        result = self.make_api_call('sys_audit', params=params)
        if result:
            records = result.get('result', [])
            logging.info(f"Found {len(records)} audit records")
            return records
        return []

    def get_user_roles(self, user_sys_id):
        """Get roles for a specific user"""
        params = {
            'sysparm_query': f'user={user_sys_id}^state=active',
            'sysparm_fields': 'role.name',
            'sysparm_display_value': 'true'
        }
        
        result = self.make_api_call('sys_user_has_role', params=params)
        if not result or not result.get('result'):
            return []
        
        roles = []
        for role_record in result['result']:
            if 'role.name' in role_record:
                roles.append(role_record['role.name'])
        return roles

    def get_user_details(self, user_sys_id):
        """Get user details"""
        params = {
            'sysparm_query': f'sys_id={user_sys_id}',
            'sysparm_fields': 'sys_id,user_name,first_name,last_name,email'
        }
        
        result = self.make_api_call('sys_user', params=params)
        if result and result.get('result'):
            user = result['result'][0]
            return {
                'sys_id': user.get('sys_id'),
                'user_name': user.get('user_name', 'Unknown'),
                'full_name': f"{user.get('first_name', '')} {user.get('last_name', '')}".strip(),
                'email': user.get('email', '')
            }
        return None

    def get_ci_type(self, document_key):
        """Get the CI type from ServiceNow"""
        logging.info(f"Getting CI type for document key: {document_key}")
        
        # First, try to get the CI details from cmdb_ci table
        params = {
            'sysparm_query': f'sys_id={document_key}',
            'sysparm_fields': 'sys_class_name'
        }
        
        result = self.make_api_call('cmdb_ci', params=params)
        if result and result.get('result'):
            ci_type = result['result'][0].get('sys_class_name', 'default')
            logging.info(f"Found CI type: {ci_type}")
            return ci_type
        
        logging.warning(f"Could not determine CI type, using default configuration")
        return 'default'

    def get_role_config(self, ci_type):
        """Get role configuration based on CI type"""
        return self.role_configs.get(ci_type, self.role_configs['default'])

    def get_field_config(self, ci_type):
        """Get field configuration based on CI type"""
        return self.field_configs.get(ci_type, self.field_configs['default'])

    def calculate_role_based_score(self, user_roles, ci_type):
        """Calculate score based on user roles and CI type"""
        score = 0
        role_config = self.get_role_config(ci_type)
        critical_roles = role_config['critical_roles']
        role_weights = role_config['role_weights']
        
        for role in user_roles:
            role_lower = role.lower()
            # Check if the role matches any critical role
            for critical_role in critical_roles:
                if critical_role in role_lower:
                    # Get the weight for this role
                    weight = role_weights.get(critical_role, 8)  # Default weight if not specified
                    score += weight
                    break  # Stop checking other critical roles once we find a match
        
        return score

    def calculate_field_based_score(self, user_changes, ci_type):
        """Calculate score based on field updates and CI type"""
        score = 0
        processed_fields = set()
        
        # Get field configuration for this CI type
        field_config = self.get_field_config(ci_type)
        critical_fields = field_config['critical_fields']
        
        for change in user_changes:
            field_name = change.get('fieldname')
            if field_name in critical_fields and field_name not in processed_fields:
                # Add score based on field importance and update count
                update_count = int(change.get('update_count', 1))
                field_score = critical_fields[field_name]
                score += field_score * min(update_count, 5)  # Cap the multiplier at 5
                processed_fields.add(field_name)
        
        return score

    def format_analysis_report(self, results):
        """Format analysis results into a readable report"""
        if not results:
            return "No analysis results available."
        
        report = []
        report.append("="*80)
        report.append("CMDB OWNERSHIP ANALYSIS SUMMARY")
        report.append("="*80)
        report.append("")
        
        # CI Information
        report.append("CI INFORMATION")
        report.append("-" * 50)
        report.append(f"CI ID: {results['ci_id']}")
        report.append(f"CI Type: {results['ci_type']}")
        report.append(f"Total Users Analyzed: {results['total_users']}")
        report.append("")
        
        # Top 5 Owners
        report.append("TOP 5 POTENTIAL OWNERS")
        report.append("-" * 50)
        
        for i, owner in enumerate(results['top_owners'][:5], 1):
            # Calculate percentages
            total_score = owner['total_score']
            role_score = owner['role_score']
            field_score = owner['field_score']
            
            role_pct = (role_score / total_score * 100) if total_score > 0 else 0
            field_pct = (field_score / total_score * 100) if total_score > 0 else 0
            
            report.append(f"{i}. {owner['name']} ({owner['username']})")
            report.append(f"   Email: {owner['email']}")
            report.append(f"   Total Score: {total_score}")
            report.append(f"   • Role Score: {role_score} ({role_pct:.1f}%)")
            report.append(f"   • Field Score: {field_score} ({field_pct:.1f}%)")
            
            if owner.get('critical_fields'):
                report.append(f"   Critical Fields Modified: {', '.join(owner['critical_fields'])}")
            report.append("")
        
        # Summary
        report.append("="*80)
        report.append(f"Most likely owner: {results['top_owners'][0]['name']} (Score: {results['top_owners'][0]['total_score']})")
        report.append("="*80)
        
        return "\n".join(report)

    def analyze_ownership(self, document_key):
        """Main method to analyze CI ownership"""
        logging.info(f"Starting ownership analysis for CI: {document_key}")
        
        # Get CI type first
        ci_type = self.get_ci_type(document_key)
        logging.info(f"Analyzing CI of type: {ci_type}")
        
        # Get field configuration
        field_config = self.get_field_config(ci_type)
        logging.info(f"Using field configuration for type: {ci_type}")
        logging.info(f"Critical fields: {list(field_config['critical_fields'].keys())}")
        
        # Get audit records
        audit_records = self.get_audit_records(document_key)
        if not audit_records:
            logging.error("No audit records found")
            return None
        
        # Process users and their activities
        user_data = {}
        for record in audit_records:
            user_sys_id = record.get('user')
            if not user_sys_id:
                continue
                
            if user_sys_id not in user_data:
                # Get user details and roles
                user_details = self.get_user_details(user_sys_id)
                if not user_details:
                    continue
                    
                user_roles = self.get_user_roles(user_sys_id)
                user_data[user_sys_id] = {
                    'details': user_details,
                    'roles': user_roles,
                    'changes': [],
                    'role_score': self.calculate_role_based_score(user_roles, ci_type)
                }
            
            user_data[user_sys_id]['changes'].append(record)
        
        # Calculate final scores and prepare results
        ownership_candidates = []
        for user_sys_id, data in user_data.items():
            field_score = self.calculate_field_based_score(data['changes'], ci_type)
            total_score = data['role_score'] + field_score
            
            # Track which fields were modified
            modified_fields = set(change['fieldname'] for change in data['changes'])
            critical_fields_modified = [f for f in modified_fields 
                                     if f in field_config['critical_fields']]
            
            ownership_candidates.append({
                'user_id': user_sys_id,
                'name': data['details']['full_name'],
                'username': data['details']['user_name'],
                'email': data['details']['email'],
                'roles': data['roles'],
                'role_score': data['role_score'],
                'field_score': field_score,
                'total_score': total_score,
                'total_changes': len(data['changes']),
                'critical_fields_modified': critical_fields_modified
            })
        
        # Sort by total score and get top 5
        ownership_candidates.sort(key=lambda x: x['total_score'], reverse=True)
        top_candidates = ownership_candidates[:5]
        
        # Log results with more detailed field information
        logging.info(f"\n=== Ownership Analysis Results for {ci_type} ===")
        for i, candidate in enumerate(top_candidates, 1):
            logging.info(f"\n{i}. {candidate['name']} ({candidate['username']})")
            logging.info(f"   Email: {candidate['email']}")
            logging.info(f"   Roles: {', '.join(candidate['roles'])}")
            logging.info(f"   Role-based Score: {candidate['role_score']}")
            logging.info(f"   Field-based Score: {candidate['field_score']}")
            logging.info(f"   Critical Fields Modified: {', '.join(candidate['critical_fields_modified'])}")
            logging.info(f"   Total Score: {candidate['total_score']}")
            logging.info(f"   Total Changes: {candidate['total_changes']}")
        
        # Format results for return
        results = {
            'ci_id': document_key,
            'ci_type': ci_type,
            'total_users': len(user_data),
            'critical_fields': list(field_config['critical_fields'].keys()),
            'top_owners': top_candidates
        }

        # Log formatted results
        logging.info("\n" + self.format_analysis_report(results))
        
        return results

# Usage Example
if __name__ == "__main__":
    try:
        print("Starting CMDB Ownership Analysis...")
        
        # Configuration
        INSTANCE_URL = "https://sandezaincdemo01.service-now.com"
        USERNAME = "parthasarathy.s"
        PASSWORD = "Partha22*"
        
        # Initialize analyzer
        analyzer = CMDBOwnershipAnalyzer(INSTANCE_URL, USERNAME, PASSWORD)
        
        # Analyze ownership for a specific CI
        CI_DOCUMENT_KEY = "006683df70194c0497052ca59602580a"
        print(f"Analyzing CI: {CI_DOCUMENT_KEY}")
        
        results = analyzer.analyze_ownership(CI_DOCUMENT_KEY)
        
        if results:
            report = analyzer.format_analysis_report(results)
            logging.info(report)  # Log the report to file
            print("Analysis complete. Check the log file for results.")
        else:
            print("No results were returned from the analysis.")
            
    except Exception as e:
        print(f"Script failed with error: {str(e)}")
        traceback.print_exc()
        sys.exit(1) 