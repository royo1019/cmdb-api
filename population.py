import requests
from requests.auth import HTTPBasicAuth
import random
from datetime import datetime, timedelta
import json

# ServiceNow instance details
INSTANCE_URL = "https://dev280836.service-now.com"
USERNAME = "admin"
PASSWORD = "Infinitywar1@"
DOCUMENT_KEY = "b4fd7c8437201000deeabfc8bcbe5dc1"

class AuditPopulator:
    def __init__(self, instance_url, username, password):
        self.instance_url = instance_url.rstrip('/')
        self.auth = HTTPBasicAuth(username, password)
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        # Will store fetched data
        self.existing_users = []
        self.field_patterns = {}
        
    def make_api_call(self, endpoint, params=None, method='GET', data=None):
        """Make API call to ServiceNow"""
        url = f"{self.instance_url}/api/now/table/{endpoint}"
        
        try:
            if method == 'GET':
                response = requests.get(url, auth=self.auth, headers=self.headers, params=params)
            elif method == 'POST':
                response = requests.post(url, auth=self.auth, headers=self.headers, json=data)
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"API call failed: {e}")
            return None

    def fetch_existing_data(self):
        """Fetch existing audit records to use as templates"""
        print("Fetching existing audit records...")
        
        params = {
            'sysparm_query': f'documentkey={DOCUMENT_KEY}',
            'sysparm_fields': 'sys_created_on,fieldname,oldvalue,newvalue,user',
            'sysparm_limit': 1000
        }
        
        result = self.make_api_call('sys_audit', params=params)
        
        if not result or not result.get('result'):
            print("No existing audit records found")
            return False
            
        records = result['result']
        print(f"Found {len(records)} existing records")
        
        # Extract unique users from the sys_audit table's "user" column
        print("\nExtracting users from sys_audit table...")
        for record in records:
            user = record.get('user')
            if user and user not in self.existing_users:
                self.existing_users.append(user)
                print(f"  Added user: {user}")
                
            fieldname = record.get('fieldname')
            if fieldname:
                if fieldname not in self.field_patterns:
                    self.field_patterns[fieldname] = {
                        'old_values': set(),
                        'new_values': set()
                    }
                
                old_val = record.get('oldvalue')
                new_val = record.get('newvalue')
                
                if old_val:
                    self.field_patterns[fieldname]['old_values'].add(old_val)
                if new_val:
                    self.field_patterns[fieldname]['new_values'].add(new_val)
        
        print(f"\n✅ Extracted {len(self.existing_users)} unique users from sys_audit table:")
        for i, user in enumerate(self.existing_users, 1):
            print(f"   {i}. {user}")
        
        print(f"\n✅ Extracted patterns for {len(self.field_patterns)} fields:")
        for field in self.field_patterns.keys():
            old_count = len(self.field_patterns[field]['old_values'])
            new_count = len(self.field_patterns[field]['new_values'])
            print(f"   - {field}: {old_count} old values, {new_count} new values")
        
        return True

    def generate_random_date(self, start_date=None):
        """Generate a random date within the last 90 days"""
        if not start_date:
            start_date = datetime.now() - timedelta(days=90)
        
        end_date = datetime.now()
        time_between_dates = end_date - start_date
        days_between_dates = time_between_dates.days
        random_number_of_days = random.randrange(days_between_dates)
        random_date = start_date + timedelta(days=random_number_of_days)
        return random_date.strftime('%Y-%m-%d %H:%M:%S')

    def create_balanced_records(self, num_records=200):
        """Create balanced random audit records using users from sys_audit table"""
        if not self.existing_users or not self.field_patterns:
            print("No template data available. Please fetch existing data first.")
            return
        
        print(f"\nGenerating {num_records} balanced audit records...")
        print(f"Using {len(self.existing_users)} users from sys_audit table")
        print(f"Using {len(self.field_patterns)} field patterns from existing records")
        
        # Calculate how many records per field to maintain balance
        records_per_field = num_records // len(self.field_patterns)
        remaining_records = num_records % len(self.field_patterns)
        
        new_records = []
        
        # Create balanced records for each field
        for fieldname, patterns in self.field_patterns.items():
            field_records = records_per_field + (1 if remaining_records > 0 else 0)
            remaining_records -= 1 if remaining_records > 0 else 0
            
            old_values = list(patterns['old_values'])
            new_values = list(patterns['new_values'])
            
            print(f"Creating {field_records} records for field '{fieldname}'")
            
            for _ in range(field_records):
                record = {
                    'documentkey': DOCUMENT_KEY,
                    'fieldname': fieldname,
                    'oldvalue': random.choice(old_values) if old_values else '',
                    'newvalue': random.choice(new_values) if new_values else '',
                    'user': random.choice(self.existing_users),  # Using users from sys_audit table
                    'sys_created_on': self.generate_random_date()
                }
                new_records.append(record)
        
        # Shuffle records to avoid patterns
        random.shuffle(new_records)
        print(f"\n✅ Generated {len(new_records)} balanced records using sys_audit users")
        return new_records

    def populate_audit_table(self, records):
        """Insert new audit records into ServiceNow"""
        print("\nPopulating audit table...")
        
        success_count = 0
        for record in records:
            result = self.make_api_call('sys_audit', method='POST', data=record)
            if result:
                success_count += 1
                print(f"Progress: {success_count}/{len(records)} records created", end='\r')
        
        print(f"\nSuccessfully created {success_count} audit records")

def main():
    populator = AuditPopulator(INSTANCE_URL, USERNAME, PASSWORD)
    
    # First fetch existing data
    if populator.fetch_existing_data():
        # Generate and insert new records
        new_records = populator.create_balanced_records(200)
        if new_records:
            populator.populate_audit_table(new_records)
    else:
        print("Failed to fetch template data. Cannot proceed.")

if __name__ == "__main__":
    main()
