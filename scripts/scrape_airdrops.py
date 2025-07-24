#!/usr/bin/env python3
"""
Advanced Crypto Airdrop Scraper
- Multi-source scraping with failover
- Proxy rotation
- Rate limiting
- Sentry error tracking
- Data validation pipeline
"""

import os
import json
import random
import time
import logging
from datetime import datetime, timedelta
from urllib.parse import urljoin
from typing import List, Dict, Optional
import argparse
import signal

import requests
from bs4 import BeautifulSoup
import sentry_sdk
from fake_useragent import UserAgent
from ratelimit import limits, sleep_and_retry
from bs4 import SoupStrainer

# Configuration
CONFIG = {
    "max_retries": 3,
    "request_timeout": 15,
    "rate_limit": 20,  # requests per minute
    "cache_expiry": timedelta(hours=1),
    "sources": {
        "coinmarketcap": {
            "url": "https://coinmarketcap.com/airdrop/",
            "parser": "parse_coinmarketcap",
            "priority": 1
        },
        "coingecko": {
            "url": "https://www.coingecko.com/en/airdrops",
            "parser": "parse_coingecko",
            "priority": 2
        },
        "airdropalert": {
            "url": "https://airdropalert.com/",
            "parser": "parse_airdropalert",
            "priority": 3,
            "requires_js": True
        }
    }
}

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scraper.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Sentry for error tracking
if os.getenv('SENTRY_DSN'):
    sentry_sdk.init(
        dsn=os.getenv('SENTRY_DSN'),
        traces_sample_rate=1.0,
        environment=os.getenv('ENVIRONMENT', 'production')
    )

class Scraper:
    """Advanced airdrop scraper with proxy support and rate limiting"""
    
    def __init__(self):
        self.session = requests.Session()
        self.ua = UserAgent()
        self.proxies = self._load_proxies()
        self.cache = {}
        self.scraped_data = []
        
    def _load_proxies(self) -> List[str]:
        """Load proxies from environment or file"""
        if os.getenv('PROXY_LIST'):
            return os.getenv('PROXY_LIST').split(',')
        try:
            with open('proxies.txt') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return []
    
    def _get_headers(self) -> Dict[str, str]:
        """Generate random headers for each request"""
        return {
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.google.com/'
        }
    
    @sleep_and_retry
    @limits(calls=CONFIG['rate_limit'], period=60)
    def _make_request(self, url: str) -> Optional[requests.Response]:
        """Make HTTP request with retries and proxy rotation"""
        headers = self._get_headers()
        proxy = random.choice(self.proxies) if self.proxies else None
        
        for attempt in range(CONFIG['max_retries']):
            try:
                if proxy:
                    response = self.session.get(
                        url,
                        headers=headers,
                        proxies={'http': proxy, 'https': proxy},
                        timeout=CONFIG['request_timeout']
                    )
                else:
                    response = self.session.get(
                        url,
                        headers=headers,
                        timeout=CONFIG['request_timeout']
                    )
                
                response.raise_for_status()
                return response
                
            except requests.exceptions.RequestException as e:
                logger.warning(f"Attempt {attempt + 1} failed for {url}: {str(e)}")
                if attempt == CONFIG['max_retries'] - 1:
                    sentry_sdk.capture_exception(e)
                    return None
                time.sleep(2 ** attempt)  # Exponential backoff

    def parse_coinmarketcap(self, html: str) -> List[Dict]:
        """Parse CoinMarketCap airdrops page"""
        strainer = SoupStrainer('div', class_='airdrop-item')
        soup = BeautifulSoup(html, 'lxml', parse_only=strainer)
        airdrops = []
        
        for item in soup.select('.airdrop-item'):
            try:
                name = item.select_one('.name').get_text(strip=True)
                link = urljoin(CONFIG['sources']['coinmarketcap']['url'], 
                              item.select_one('a')['href'])
                
                airdrops.append({
                    'name': name,
                    'link': link,
                    'source': 'coinmarketcap',
                    'scraped_at': datetime.utcnow().isoformat(),
                    'metadata': {
                        'status': item.select_one('.status')['title'],
                        'value': item.select_one('.value').get_text(strip=True)
                    }
                })
            except Exception as e:
                logger.error(f"Error parsing CMC item: {str(e)}")
                continue
                
        return airdrops
    
    def parse_coingecko(self, html: str) -> List[Dict]:
        """Parse CoinGecko airdrops page"""
        soup = BeautifulSoup(html, 'lxml')
        airdrops = []
        
        for row in soup.select('table tbody tr'):
            try:
                cols = row.select('td')
                if len(cols) < 5:
                    continue
                    
                airdrops.append({
                    'name': cols[1].get_text(strip=True),
                    'link': urljoin(CONFIG['sources']['coingecko']['url'], 
                                  cols[1].select_one('a')['href']),
                    'source': 'coingecko',
                    'scraped_at': datetime.utcnow().isoformat(),
                    'metadata': {
                        'platform': cols[2].get_text(strip=True),
                        'end_date': cols[3].get_text(strip=True),
                        'value': cols[4].get_text(strip=True)
                    }
                })
            except Exception as e:
                logger.error(f"Error parsing CoinGecko item: {str(e)}")
                continue
                
        return airdrops
    
    def parse_airdropalert(self, html: str) -> List[Dict]:
        """Parse AirdropAlert page (requires JS rendering)"""
        # This would normally use Selenium/Playwright
        # Simplified version for demo
        soup = BeautifulSoup(html, 'lxml')
        airdrops = []
        
        for card in soup.select('.airdrop-card'):
            try:
                airdrops.append({
                    'name': card.select_one('.title').get_text(strip=True),
                    'link': card.select_one('a')['href'],
                    'source': 'airdropalert',
                    'scraped_at': datetime.utcnow().isoformat(),
                    'metadata': {
                        'rating': card.select_one('.rating')['title'],
                        'tokens': card.select_one('.tokens').get_text(strip=True)
                    }
                })
            except Exception as e:
                logger.error(f"Error parsing AirdropAlert item: {str(e)}")
                continue
                
        return airdrops
    
    def scrape_source(self, source_name: str) -> List[Dict]:
        """Scrape a single source with caching"""
        source = CONFIG['sources'][source_name]
        cache_key = f"{source_name}_{datetime.utcnow().strftime('%Y%m%d%H')}"
        
        # Check cache
        if cache_key in self.cache:
            if datetime.utcnow() - self.cache[cache_key]['timestamp'] < CONFIG['cache_expiry']:
                return self.cache[cache_key]['data']
        
        logger.info(f"Scraping {source_name}...")
        response = self._make_request(source['url'])
        if not response:
            return []
            
        parser = getattr(self, source['parser'])
        data = parser(response.text)
        
        # Update cache
        self.cache[cache_key] = {
            'data': data,
            'timestamp': datetime.utcnow()
        }
        
        return data
    
    def run(self, max_items: int = 100) -> None:
        """Main scraping pipeline"""
        logger.info("Starting scraping process")
        
        # Handle graceful shutdown
        def signal_handler(sig, frame):
            logger.info("Received shutdown signal, saving progress...")
            self.save_results()
            exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Scrape all sources
        for source_name in sorted(CONFIG['sources'], 
                                key=lambda x: CONFIG['sources'][x]['priority']):
            try:
                self.scraped_data.extend(self.scrape_source(source_name))
                if len(self.scraped_data) >= max_items:
                    break
            except Exception as e:
                logger.error(f"Failed to scrape {source_name}: {str(e)}")
                sentry_sdk.capture_exception(e)
                continue
                
        self.save_results()
        logger.info(f"Scraping complete. Found {len(self.scraped_data)} airdrops")
    
    def save_results(self) -> None:
        """Save results to JSON file with backup"""
        output = {
            'metadata': {
                'generated_at': datetime.utcnow().isoformat(),
                'source_count': len(self.scraped_data),
                'sources': list(CONFIG['sources'].keys())
            },
            'data': self.scraped_data
        }
        
        # Write to primary file
        with open('sources.json', 'w') as f:
            json.dump(output, f, indent=2)
            
        # Create timestamped backup
        backup_file = f"backups/sources_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.json"
        os.makedirs('backups', exist_ok=True)
        with open(backup_file, 'w') as f:
            json.dump(output, f)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--max', type=int, default=100, 
                       help='Maximum number of airdrops to collect')
    parser.add_argument('--retry', type=int, default=1,
                       help='Retry attempt number for logging')
    args = parser.parse_args()
    
    logger.info(f"Starting scraper (Attempt {args.retry}, Max {args.max} items)")
    scraper = Scraper()
    scraper.run(max_items=args.max)