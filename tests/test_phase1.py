import os
import unittest
import time
import uuid
import socket
import redis
import psycopg2
from dotenv import load_dotenv

# Load environment variables
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))

class TestPhase1(unittest.TestCase):

    def setUp(self):
        self.redis_host = os.getenv('REDIS_HOST', 'localhost')
        self.redis_port = int(os.getenv('REDIS_PORT', 6379))
        self.redis_password = os.getenv('REDIS_PASSWORD')
        
        self.pg_host = os.getenv('POSTGRES_HOST', 'localhost')
        self.pg_port = int(os.getenv('POSTGRES_PORT', 5432))
        self.pg_db = os.getenv('POSTGRES_DB', 'securisphere_db')
        self.pg_user = os.getenv('POSTGRES_USER', 'securisphere_user')
        self.pg_password = os.getenv('POSTGRES_PASSWORD', 'securisphere_pass_2024')

        # Fallback to localhost if hostnames are not resolvable (running locally)
        self.redis_host = self._resolve_host(self.redis_host)
        self.pg_host = self._resolve_host(self.pg_host)

    def _resolve_host(self, host):
        try:
            socket.gethostbyname(host)
            return host
        except socket.error:
            return 'localhost'


    def test_redis_connection_and_ping(self):
        """Test Redis connection and PING response"""
        try:
            r = redis.Redis(host=self.redis_host, port=self.redis_port, password=self.redis_password)
            self.assertTrue(r.ping(), "Redis PING failed")
        except Exception as e:
            self.fail(f"Redis connection failed: {e}")

    def test_postgres_connection(self):
        """Test PostgreSQL connection"""
        try:
            conn = psycopg2.connect(
                host=self.pg_host,
                port=self.pg_port,
                dbname=self.pg_db,
                user=self.pg_user,
                password=self.pg_password
            )
            self.assertIsNotNone(conn)
            conn.close()
        except Exception as e:
            self.fail(f"PostgreSQL connection failed: {e}")

    def test_postgres_tables_exist(self):
        """Test that all 4 tables exist in database"""
        expected_tables = {'security_events', 'correlated_incidents', 'risk_scores', 'baseline_metrics'}
        try:
            conn = psycopg2.connect(
                host=self.pg_host,
                port=self.pg_port,
                dbname=self.pg_db,
                user=self.pg_user,
                password=self.pg_password
            )
            cur = conn.cursor()
            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public';")
            tables = {row[0] for row in cur.fetchall()}
            conn.close()
            
            self.assertTrue(expected_tables.issubset(tables), f"Missing tables: {expected_tables - tables}")
        except Exception as e:
            self.fail(f"Database query failed: {e}")

    def test_postgres_indexes_exist(self):
        """Test that all indexes exist"""
        expected_indexes = {
            'idx_events_timestamp', 'idx_events_source_ip', 'idx_events_event_type', 
            'idx_events_source_layer', 'idx_events_severity', 
            'idx_incidents_timestamp', 'idx_incidents_severity', 'idx_incidents_source_ip', 
            'idx_risk_entity', 'idx_baseline_entity'
        }
        try:
            conn = psycopg2.connect(
                host=self.pg_host,
                port=self.pg_port,
                dbname=self.pg_db,
                user=self.pg_user,
                password=self.pg_password
            )
            cur = conn.cursor()
            cur.execute("SELECT indexname FROM pg_indexes WHERE schemaname = 'public';")
            indexes = {row[0] for row in cur.fetchall()}
            conn.close()
            
            self.assertTrue(expected_indexes.issubset(indexes), f"Missing indexes: {expected_indexes - indexes}")
        except Exception as e:
            self.fail(f"Database query failed: {e}")

    def test_redis_pubsub(self):
        """Test Redis pub/sub by publishing and receiving a message"""
        channel = 'test_channel'
        message = 'test_message'
        
        try:
            r = redis.Redis(host=self.redis_host, port=self.redis_port, password=self.redis_password)
            pubsub = r.pubsub()
            pubsub.subscribe(channel)
            
            # Verify subscription
            # Iterate to ignore the subscribe message if needed
            # But simpler to just publish and check return
            
            # Wait a tiny bit for subscription to register
            time.sleep(0.1)
            
            subscribers = r.publish(channel, message)
            self.assertGreaterEqual(subscribers, 1, "No subscribers received the message")
            
            # Retry getting message
            start_time = time.time()
            msg = None
            while time.time() - start_time < 2.0:
                msg = pubsub.get_message(ignore_subscribe_messages=True)
                if msg:
                    break
                time.sleep(0.1)
                
            self.assertIsNotNone(msg, "Did not receive message from Pub/Sub")
            self.assertEqual(msg['data'].decode('utf-8'), message)
            pubsub.close()
        except Exception as e:
            self.fail(f"Redis Pub/Sub failed: {e}")

    def test_postgres_insert_select(self):
        """Test PostgreSQL insert and select on security_events table"""
        test_event_id = str(uuid.uuid4())
        try:
            conn = psycopg2.connect(
                host=self.pg_host,
                port=self.pg_port,
                dbname=self.pg_db,
                user=self.pg_user,
                password=self.pg_password
            )
            cur = conn.cursor()
            
            # Insert
            cur.execute("""
                INSERT INTO security_events (
                    event_id, timestamp, source_layer, source_monitor, event_category, 
                    event_type, severity_level, severity_score, source_ip
                ) VALUES (
                    %s, NOW(), 'test_layer', 'test_monitor', 'test_category', 
                    'test_type', 'INFO', 0, '127.0.0.1'
                )
            """, (test_event_id,))
            conn.commit()
            
            # Select
            cur.execute("SELECT event_id FROM security_events WHERE event_id = %s", (test_event_id,))
            result = cur.fetchone()
            
            self.assertIsNotNone(result)
            self.assertEqual(str(result[0]), test_event_id)
            
            # Clean up
            cur.execute("DELETE FROM security_events WHERE event_id = %s", (test_event_id,))
            conn.commit()
            
            cur.close()
            conn.close()
        except Exception as e:
            self.fail(f"PostgreSQL operations failed: {e}")

if __name__ == '__main__':
    unittest.main()
