#!/usr/bin/env python3
"""
Fix Kibana Data Views to point to actual indices with data
"""

import requests
import json

def update_data_view(data_view_id, new_title, new_name):
    """Update a data view to point to actual indices"""
    url = f"http://localhost:5601/api/data_views/data_view/{data_view_id}"
    
    headers = {
        'kbn-xsrf': 'true',
        'Content-Type': 'application/json'
    }
    
    data = {
        'data_view': {
            'title': new_title,
            'name': new_name,
            'timeFieldName': '@timestamp'
        }
    }
    
    try:
        response = requests.put(url, headers=headers, json=data)
        if response.status_code == 200:
            print(f"✅ Updated {new_name}: {new_title}")
            return True
        else:
            print(f"❌ Failed to update {new_name}: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error updating {new_name}: {e}")
        return False

def main():
    """Update all data views to point to actual indices with data"""
    
    # Data view ID mappings (from the curl output above)
    updates = [
        # (data_view_id, new_title, new_name)
        ("a94afe88-ad01-45c6-8827-543978304fc2", "framework-comparison*", "Framework Comparison"),
        ("14ddb16b-1b6b-4214-a0c4-db58cc2417d5", "mfa-events", "Security Metrics"),  # mfa-events has the security data
        ("b8586057-9573-4478-8a0b-d0c26b05c263", "baseline-decisions", "User Experience"),  # baseline-decisions has user experience data
        ("837214d3-f83c-4c08-9d2d-70813bda753c", "security-classifications*", "Privacy Metrics"),  # security classifications
        ("d994bc70-a531-4d0c-bf75-aa5a621a0c8f", "siem-alerts", "STRIDE Alerts"),  # siem-alerts matches stride-alerts
        ("67792a58-ad9d-4aa4-beb1-bb6d394df975", "mfa-events", "Failed Logins"),  # mfa-events contains login decisions
        ("6b020a5c-93a8-4ea6-9792-60a0f3eba769", "mfa-events", "Decision Latency"),  # mfa-events has timing data
        ("bbac233e-2872-446b-b592-f810c215d908", "validated-context", "Validation Logs")  # validated-context has validation data
    ]
    
    print("Updating Kibana data views to point to actual indices with data...")
    
    success_count = 0
    for data_view_id, new_title, new_name in updates:
        if update_data_view(data_view_id, new_title, new_name):
            success_count += 1
    
    print(f"\n✅ Successfully updated {success_count}/{len(updates)} data views")
    print("\n🎯 Your Kibana dashboards should now show data!")
    print("Refresh your browser and check the dashboards.")

if __name__ == "__main__":
    main()
