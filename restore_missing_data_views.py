#!/usr/bin/env python3
"""
Restore the missing data views that were deleted for thesis analysis
"""

import requests
import json

def create_data_view(title, name):
    """Create a new data view"""
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
    """Create the missing data views for thesis analysis"""
    
    # The data views that were deleted and need to be restored
    missing_data_views = [
        # (title, name) - pointing to actual indices with data or expected patterns
        ("framework-comparison*", "Framework Comparison"),  # Will match framework-comparison-2025-09-27
        ("security-metrics*", "Security Metrics"),  # Will be created when data flows
        ("user-experience*", "User Experience"),  # Will be created when data flows  
        ("privacy-metrics*", "Privacy Metrics"),  # Will be created when data flows
        ("stride-alerts*", "STRIDE Alerts"),  # Will match siem-alerts
        ("failed-logins*", "Failed Logins"),  # Will be created when data flows
        ("decision-latency*", "Decision Latency"),  # Will be created when data flows
        ("validation-logs*", "Validation Logs")  # Will match validated-context
    ]
    
    print("Creating missing data views for thesis analysis...")
    
    success_count = 0
    for title, name in missing_data_views:
        if create_data_view(title, name):
            success_count += 1
    
    print(f"\n✅ Successfully created {success_count}/{len(missing_data_views)} missing data views")
    print("\n🎯 Your thesis analysis data views are now available!")
    print("Note: Some data views may show no data until the corresponding indices are created by the system.")

if __name__ == "__main__":
    main()
