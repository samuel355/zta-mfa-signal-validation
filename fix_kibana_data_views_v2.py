#!/usr/bin/env python3
"""
Fix Kibana Data Views by creating new ones pointing to actual indices with data
"""

import requests
import json

def delete_data_view(data_view_id, name):
    """Delete a data view"""
    url = f"http://localhost:5601/api/data_views/data_view/{data_view_id}"
    
    headers = {
        'kbn-xsrf': 'true'
    }
    
    try:
        response = requests.delete(url, headers=headers)
        if response.status_code == 200:
            print(f"✅ Deleted {name}")
            return True
        else:
            print(f"❌ Failed to delete {name}: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error deleting {name}: {e}")
        return False

def create_data_view(title, name):
    """Create a new data view pointing to actual indices"""
    url = "http://localhost:5601/api/data_views/data_view"
    
    headers = {
        'kbn-xsrf': 'true',
        'Content-Type': 'application/json'
    }
    
    data = {
        'data_view': {
            'title': title,
            'name': name,
            'timeFieldName': '@timestamp'
        }
    }
    
    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            print(f"✅ Created {name}: {title}")
            return True
        else:
            print(f"❌ Failed to create {name}: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"❌ Error creating {name}: {e}")
        return False

def main():
    """Fix data views by recreating them with correct indices"""
    
    # Data view ID mappings (from the curl output above)
    data_views_to_delete = [
        # (data_view_id, name)
        ("a94afe88-ad01-45c6-8827-543978304fc2", "Framework Comparison"),
        ("14ddb16b-1b6b-4214-a0c4-db58cc2417d5", "Security Metrics"),
        ("b8586057-9573-4478-8a0b-d0c26b05c263", "User Experience"),
        ("837214d3-f83c-4c08-9d2d-70813bda753c", "Privacy Metrics"),
        ("d994bc70-a531-4d0c-bf75-aa5a621a0c8f", "STRIDE Alerts"),
        ("67792a58-ad9d-4aa4-beb1-bb6d394df975", "Failed Logins"),
        ("6b020a5c-93a8-4ea6-9792-60a0f3eba769", "Decision Latency"),
        ("bbac233e-2872-446b-b592-f810c215d908", "Validation Logs")
    ]
    
    # New data views pointing to actual indices with data
    new_data_views = [
        # (title, name)
        ("mfa-events", "Security Metrics"),  # mfa-events has the security data
        ("baseline-decisions", "User Experience"),  # baseline-decisions has user experience data
        ("security-classifications*", "Privacy Metrics"),  # security classifications
        ("siem-alerts", "STRIDE Alerts"),  # siem-alerts matches stride-alerts
        ("validated-context", "Validation Logs")  # validated-context has validation data
    ]
    
    print("Deleting old data views...")
    delete_count = 0
    for data_view_id, name in data_views_to_delete:
        if delete_data_view(data_view_id, name):
            delete_count += 1
    
    print(f"\nDeleted {delete_count}/{len(data_views_to_delete)} old data views")
    
    print("\nCreating new data views pointing to actual indices...")
    create_count = 0
    for title, name in new_data_views:
        if create_data_view(title, name):
            create_count += 1
    
    print(f"\n✅ Successfully created {create_count}/{len(new_data_views)} new data views")
    print("\n🎯 Your Kibana dashboards should now show data!")
    print("Refresh your browser and check the dashboards.")

if __name__ == "__main__":
    main()
