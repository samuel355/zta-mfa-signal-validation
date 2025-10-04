#!/usr/bin/env python3
"""
Populate security_classifications table with realistic data for true positives, false positives, etc.
"""

import os
import sys
import random
import json
from datetime import datetime, timedelta
from sqlalchemy import create_engine, text

def get_db_connection():
    """Get database connection using SQLAlchemy"""
    try:
        dsn = os.getenv('DB_DSN', '').strip()
        if not dsn:
            return None
        if dsn.startswith('postgresql://'):
            dsn = 'postgresql+psycopg://' + dsn[len('postgresql://'):]
        elif dsn.startswith('postgres://'):
            dsn = 'postgresql+psycopg://' + dsn[len('postgres://'):]
        if 'sslmode=' not in dsn:
            dsn += ('&' if '?' in dsn else '?') + 'sslmode=require'
        
        engine = create_engine(dsn, pool_pre_ping=True, future=True)
        return engine
    except Exception as e:
        print(f"Database connection failed: {e}")
        return None

def generate_security_classifications_data(engine, num_records=1000):
    """Generate realistic security classification data"""
    
    with engine.begin() as conn:
        try:
            # Clear existing data
            conn.execute(text("DELETE FROM zta.security_classifications"))
            print("Cleared existing security_classifications data")
            
            # Generate realistic data
            threat_types = ['malware', 'phishing', 'brute_force', 'data_exfiltration', 'insider_threat', 'ddos']
            frameworks = ['baseline', 'proposed']
            labels = ['benign', 'malicious']
            
            # Realistic distribution: 70% benign, 30% malicious
            # Of malicious: 95% true positive, 5% false negative (improved baseline)
            # Of benign: 85% true negative, 15% false positive (more realistic)
            
            for i in range(num_records):
                session_id = f"session_security_{i:06d}"
                
                # Determine ground truth
                is_malicious = random.random() < 0.3  # 30% malicious
                original_label = 'malicious' if is_malicious else 'benign'
                
                # Generate predicted threats based on ground truth
                if is_malicious:
                    # True positive: correctly identify malicious
                    if random.random() < 0.95:  # 95% true positive rate (improved baseline)
                        predicted_threats = [random.choice(threat_types)]
                        false_positive = False
                        false_negative = False
                    else:
                        # False negative: miss malicious activity
                        predicted_threats = []
                        false_positive = False
                        false_negative = True
                else:
                    # Benign case
                    if random.random() < 0.85:  # 85% true negative rate (more realistic)
                        predicted_threats = []
                        false_positive = False
                        false_negative = False
                    else:
                        # False positive: incorrectly flag benign as malicious
                        predicted_threats = [random.choice(threat_types)]
                        false_positive = True
                        false_negative = False
                
                # Generate actual threats (ground truth)
                actual_threats = [random.choice(threat_types)] if is_malicious else []
                
                # Calculate classification accuracy
                if false_positive or false_negative:
                    classification_accuracy = 0.0
                else:
                    classification_accuracy = 1.0
                
                # Random framework type
                framework_type = random.choice(frameworks)
                
                # Random timestamp within last 30 days
                created_at = datetime.utcnow() - timedelta(
                    days=random.randint(0, 30),
                    hours=random.randint(0, 23),
                    minutes=random.randint(0, 59)
                )
                
                # Insert record
                conn.execute(text("""
                    INSERT INTO zta.security_classifications 
                    (session_id, original_label, predicted_threats, actual_threats, 
                     framework_type, classification_accuracy, false_positive, false_negative, created_at)
                    VALUES (:session_id, :original_label, :predicted_threats, :actual_threats, 
                            :framework_type, :classification_accuracy, :false_positive, :false_negative, :created_at)
                """), {
                    'session_id': session_id,
                    'original_label': original_label,
                    'predicted_threats': json.dumps(predicted_threats),
                    'actual_threats': json.dumps(actual_threats),
                    'framework_type': framework_type,
                    'classification_accuracy': classification_accuracy,
                    'false_positive': false_positive,
                    'false_negative': false_negative,
                    'created_at': created_at
                })
            
            print(f"Generated {num_records} security classification records")
            
            # Print summary statistics
            result = conn.execute(text("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN false_positive THEN 1 ELSE 0 END) as false_positives,
                    SUM(CASE WHEN false_negative THEN 1 ELSE 0 END) as false_negatives,
                    SUM(CASE WHEN NOT false_positive AND NOT false_negative THEN 1 ELSE 0 END) as correct_classifications,
                    AVG(classification_accuracy) as avg_accuracy
                FROM zta.security_classifications
            """))
            
            stats = result.fetchone()
            print(f"\nSummary Statistics:")
            print(f"Total records: {stats[0]}")
            print(f"False positives: {stats[1]}")
            print(f"False negatives: {stats[2]}")
            print(f"Correct classifications: {stats[3]}")
            print(f"Average accuracy: {stats[4]:.3f}" if stats[4] else "Average accuracy: N/A")
            
        except Exception as e:
            print(f"Error generating data: {e}")
            raise

def main():
    """Main function"""
    print("Populating security_classifications table with realistic data...")
    
    engine = get_db_connection()
    if engine is None:
        print("Failed to connect to database")
        sys.exit(1)
    
    try:
        generate_security_classifications_data(engine, num_records=1000)
    finally:
        engine.dispose()
    
    print("Done!")

if __name__ == "__main__":
    main()
