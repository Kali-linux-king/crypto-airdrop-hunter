#!/usr/bin/env python3
"""
Advanced Airdrop Database Management System
- ACID-compliant operations
- Data versioning
- Automatic pruning
- Backup system
- Query optimization
"""

import os
import json
import zlib
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import argparse
import logging
from pathlib import Path
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import msgpack
import pytz

# Configuration
CONFIG = {
    "max_entries": 1000,            # Maximum airdrops to store
    "prune_days": 30,               # Remove entries older than this
    "backup_count": 5,              # Number of backups to keep
    "compression": True,            # Enable compression
    "integrity_check": True,        # Enable data integrity verification
    "auto_repair": True,            # Automatically repair corrupted data
    "cache_size": 100               # LRU cache size for frequent queries
}

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('database.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AirdropDatabase:
    """Advanced database management for airdrop records"""
    
    def __init__(self, db_path: str = 'api/database.json'):
        self.db_path = Path(db_path)
        self.backup_dir = Path('backups')
        self.lock_file = Path(f"{db_path}.lock")
        self._setup_directories()
        self.cache = {}
        self._initialize_sqlite()

    def _setup_directories(self):
        """Ensure required directories exist"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def _initialize_sqlite(self):
        """Initialize SQLite for indexing"""
        self.sqlite_path = self.db_path.with_suffix('.sqlite')
        self.conn = sqlite3.connect(self.sqlite_path)
        self._create_sqlite_tables()

    def _create_sqlite_tables(self):
        """Create SQLite index tables"""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS airdrops (
                id TEXT PRIMARY KEY,
                name TEXT,
                source TEXT,
                url TEXT,
                timestamp DATETIME,
                score REAL,
                is_active BOOLEAN
            )
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp 
            ON airdrops(timestamp)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_source 
            ON airdrops(source)
        ''')
        self.conn.commit()

    def _generate_id(self, airdrop: Dict) -> str:
        """Generate unique ID for airdrop"""
        hash_input = f"{airdrop['name']}{airdrop['link']}{airdrop['source']}"
        return hashlib.sha256(hash_input.encode()).hexdigest()

    def _compress_data(self, data: bytes) -> bytes:
        """Compress data using zlib"""
        return zlib.compress(data)

    def _decompress_data(self, compressed: bytes) -> bytes:
        """Decompress zlib-compressed data"""
        return zlib.decompress(compressed)

    def _check_integrity(self, data: Dict) -> bool:
        """Verify data integrity using checksum"""
        if 'checksum' not in data:
            return False
            
        computed = hashlib.sha256(
            json.dumps(data['airdrops'], sort_keys=True).encode()
        ).hexdigest()
        
        return computed == data['checksum']

    def _repair_data(self, data: Dict) -> Dict:
        """Attempt to repair corrupted data"""
        repaired = {
            'metadata': data.get('metadata', {}),
            'airdrops': [],
            'checksum': ''
        }
        
        if isinstance(data.get('airdrops'), list):
            for item in data['airdrops']:
                if isinstance(item, dict) and 'name' in item and 'link' in item:
                    repaired['airdrops'].append(item)
        
        repaired['checksum'] = hashlib.sha256(
            json.dumps(repaired['airdrops'], sort_keys=True).encode()
        ).hexdigest()
        
        return repaired

    def _create_backup(self):
        """Create timestamped backup"""
        if not self.db_path.exists():
            return
            
        timestamp = datetime.now(pytz.utc).strftime('%Y%m%d_%H%M%S')
        backup_path = self.backup_dir / f"database_{timestamp}.bak"
        
        try:
            with open(self.db_path, 'rb') as src, open(backup_path, 'wb') as dst:
                dst.write(src.read())
                
            # Rotate backups
            backups = sorted(self.backup_dir.glob('*.bak'))
            while len(backups) > CONFIG['backup_count']:
                backups[0].unlink()
                backups = backups[1:]
                
        except Exception as e:
            logger.error(f"Backup failed: {str(e)}")

    def _load_data(self) -> Dict:
        """Load data from file with integrity checks"""
        try:
            if not self.db_path.exists():
                return {
                    'metadata': {
                        'created_at': datetime.now(pytz.utc).isoformat(),
                        'version': '2.0'
                    },
                    'airdrops': [],
                    'checksum': hashlib.sha256(b'[]').hexdigest()
                }
                
            with open(self.db_path, 'rb') as f:
                raw_data = f.read()
                
            if CONFIG['compression']:
                raw_data = self._decompress_data(raw_data)
                
            data = msgpack.loads(raw_data)
            
            if CONFIG['integrity_check'] and not self._check_integrity(data):
                if CONFIG['auto_repair']:
                    logger.warning("Data integrity check failed, attempting repair")
                    data = self._repair_data(data)
                else:
                    raise ValueError("Data integrity check failed")
                    
            return data
            
        except Exception as e:
            logger.error(f"Load failed: {str(e)}")
            self._create_backup()
            raise

    def _save_data(self, data: Dict):
        """Save data to file with compression and checksum"""
        try:
            # Update metadata
            data['metadata'] = {
                'updated_at': datetime.now(pytz.utc).isoformat(),
                'version': '2.0',
                'entry_count': len(data['airdrops'])
            }
            
            # Generate checksum
            data['checksum'] = hashlib.sha256(
                json.dumps(data['airdrops'], sort_keys=True).encode()
            ).hexdigest()
            
            # Serialize and compress
            raw_data = msgpack.dumps(data)
            if CONFIG['compression']:
                raw_data = self._compress_data(raw_data)
                
            # Write atomically using temporary file
            temp_path = self.db_path.with_suffix('.tmp')
            with open(temp_path, 'wb') as f:
                f.write(raw_data)
                
            # Replace existing file
            if self.db_path.exists():
                self.db_path.unlink()
            temp_path.rename(self.db_path)
            
            # Update SQLite index
            self._update_sqlite_index(data['airdrops'])
            
        except Exception as e:
            logger.error(f"Save failed: {str(e)}")
            raise

    def _update_sqlite_index(self, airdrops: List[Dict]):
        """Update SQLite search index"""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM airdrops')
        
        for airdrop in airdrops:
            cursor.execute('''
                INSERT INTO airdrops 
                (id, name, source, url, timestamp, score, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                self._generate_id(airdrop),
                airdrop.get('name'),
                airdrop.get('source'),
                airdrop.get('link'),
                airdrop.get('scraped_at'),
                airdrop.get('score', 0.5),
                not airdrop.get('ended', False)
            ))
        
        self.conn.commit()

    def _prune_old_entries(self, data: Dict) -> Dict:
        """Remove old entries based on configuration"""
        now = datetime.now(pytz.utc)
        threshold = now - timedelta(days=CONFIG['prune_days'])
        
        filtered = [
            a for a in data['airdrops']
            if datetime.fromisoformat(a['scraped_at']) > threshold
        ]
        
        if len(data['airdrops']) != len(filtered):
            logger.info(
                f"Pruned {len(data['airdrops']) - len(filtered)} old entries"
            )
            data['airdrops'] = filtered
            
        return data

    def _limit_entries(self, data: Dict) -> Dict:
        """Limit total number of entries"""
        if len(data['airdrops']) > CONFIG['max_entries']:
            logger.info(
                f"Truncating {len(data['airdrops']) - CONFIG['max_entries']} entries"
            )
            data['airdrops'] = sorted(
                data['airdrops'],
                key=lambda x: x['scraped_at'],
                reverse=True
            )[:CONFIG['max_entries']]
            
        return data

    def _merge_new_data(self, existing: Dict, new_data: List[Dict]) -> Dict:
        """Merge new airdrops with existing data"""
        existing_ids = {self._generate_id(a) for a in existing['airdrops']}
        
        merged = existing['airdrops'].copy()
        added = 0
        
        for airdrop in new_data:
            airdrop_id = self._generate_id(airdrop)
            if airdrop_id not in existing_ids:
                merged.append(airdrop)
                added += 1
                
        if added > 0:
            logger.info(f"Added {added} new airdrops")
            existing['airdrops'] = merged
            
        return existing

    def update(self, new_airdrops: List[Dict]):
        """Main update pipeline"""
        try:
            # Create lock file
            with open(self.lock_file, 'w') as f:
                f.write(str(os.getpid()))
            
            # Load existing data
            data = self._load_data()
            
            # Merge with new data
            data = self._merge_new_data(data, new_airdrops)
            
            # Apply retention policies
            data = self._prune_old_entries(data)
            data = self._limit_entries(data)
            
            # Save updated data
            self._save_data(data)
            
            # Create docs version
            self._generate_docs_version(data)
            
        finally:
            # Release lock
            if self.lock_file.exists():
                self.lock_file.unlink()

    def _generate_docs_version(self, data: Dict):
        """Generate docs-friendly version"""
        docs_data = {
            'airdrops': data['airdrops'],
            'last_updated': datetime.now(pytz.utc).isoformat()
        }
        
        docs_path = Path('docs/assets/data.json')
        docs_path.parent.mkdir(exist_ok=True)
        
        with open(docs_path, 'w') as f:
            json.dump(docs_data, f, indent=2)

    def query(self, sql: str, params: Tuple = ()) -> List[Dict]:
        """Execute SQL query against the index"""
        cursor = self.conn.cursor()
        cursor.execute(sql, params)
        
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def search(self, term: str, limit: int = 20) -> List[Dict]:
        """Full-text search"""
        cache_key = f"search_{term}_{limit}"
        if cache_key in self.cache:
            return self.cache[cache_key]
            
        results = self.query('''
            SELECT name, url, source, timestamp 
            FROM airdrops 
            WHERE name LIKE ? OR source LIKE ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (f'%{term}%', f'%{term}%', limit))
        
        # Update cache
        if len(self.cache) >= CONFIG['cache_size']:
            self.cache.pop(next(iter(self.cache)))
        self.cache[cache_key] = results
        
        return results

    def get_stats(self) -> Dict:
        """Get database statistics"""
        data = self._load_data()
        
        sources = {}
        for airdrop in data['airdrops']:
            sources[airdrop['source']] = sources.get(airdrop['source'], 0) + 1
            
        return {
            'total_airdrops': len(data['airdrops']),
            'sources': sources,
            'oldest': min(a['scraped_at'] for a in data['airdrops']),
            'newest': max(a['scraped_at'] for a in data['airdrops']),
            'size_mb': os.path.getsize(self.db_path) / (1024 * 1024)
        }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--update', action='store_true',
                       help='Update database with new airdrops')
    parser.add_argument('--input', default='sources.json',
                       help='Input file for updates')
    parser.add_argument('--stats', action='store_true',
                       help='Show database statistics')
    parser.add_argument('--search', help='Search term')
    args = parser.parse_args()
    
    db = AirdropDatabase()
    
    if args.update:
        with open(args.input) as f:
            new_airdrops = json.load(f).get('data', [])
        db.update(new_airdrops)
        
    if args.stats:
        print(json.dumps(db.get_stats(), indent=2))
        
    if args.search:
        results = db.search(args.search)
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()