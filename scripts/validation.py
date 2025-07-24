#!/usr/bin/env python3
"""
Advanced Airdrop Validation Pipeline
- Multi-layer validation
- Scam detection
- Data normalization
- Threat analysis
"""

import re
import json
from datetime import datetime, timedelta
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple
import argparse
import logging
import hashlib
import tldextract
import idna
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AirdropValidator:
    """Advanced validation system for crypto airdrops"""
    
    def __init__(self):
        # Compiled regex patterns for performance
        self._compile_patterns()
        
        # Known scam indicators database
        self.scam_db = self._load_scam_database()
        
        # Domain reputation thresholds
        self.reputation_thresholds = {
            'age_days': 30,
            'alexa_rank': 1000000,
            'ssl_verified': True
        }

    def _compile_patterns(self):
        """Pre-compile all regex patterns"""
        self.patterns = {
            'scam_phrases': re.compile(
                r'(free\s*(money|coin|token)|double\s*your|instant\s*rewards|'
                r'guaranteed\s*profit|limited\s*time|no\s*investment)',
                re.IGNORECASE
            ),
            'suspicious_domains': re.compile(
                r'(airdrop|bounty|freecoin|claimtoken)\.(com|io|xyz)'
            ),
            'eth_address': re.compile(r'^0x[a-fA-F0-9]{40}$'),
            'btc_address': re.compile(
                r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|'
                r'^bc1[a-z0-9]{39,59}$'
            ),
            'malicious_ext': re.compile(
                r'\.(exe|msi|bat|cmd|scr|jar)$', 
                re.IGNORECASE
            )
        }

    def _load_scam_database(self) -> Dict:
        """Load known scam indicators from file or API"""
        try:
            with open('scam_indicators.json') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                'blacklisted_domains': [],
                'known_scam_words': [],
                'malicious_patterns': []
            }

    def validate_structure(self, airdrop: Dict) -> Tuple[bool, List[str]]:
        """Validate basic airdrop structure"""
        required_fields = {
            'name': (str, 3, 100),
            'link': (str, 10, 200),
            'source': (str, 2, 50),
            'scraped_at': (str, 10, 30)
        }
        
        errors = []
        
        # Check required fields
        for field, (field_type, min_len, max_len) in required_fields.items():
            if field not in airdrop:
                errors.append(f"Missing required field: {field}")
                continue
                
            if not isinstance(airdrop[field], field_type):
                errors.append(f"Invalid type for {field}. Expected {field_type}")
                
            if isinstance(airdrop[field], str):
                if len(airdrop[field]) < min_len:
                    errors.append(f"{field} too short (min {min_len} chars)")
                if len(airdrop[field]) > max_len:
                    errors.append(f"{field} too long (max {max_len} chars)")
        
        return (len(errors) == 0, errors)

    def validate_url(self, url: str) -> Tuple[bool, List[str]]:
        """Deep URL validation with security checks"""
        errors = []
        
        try:
            # Basic URL parsing
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                errors.append("Invalid URL structure")
                return (False, errors)
                
            # Scheme validation
            if parsed.scheme not in ['http', 'https']:
                errors.append("Unsupported URL scheme")
                
            # IDNA/punycode check for international domains
            try:
                idna.encode(parsed.netloc)
            except idna.core.IDNAError:
                errors.append("Invalid international domain encoding")
                
            # Domain analysis
            domain_info = tldextract.extract(parsed.netloc)
            
            # Check for suspicious domain patterns
            if self.patterns['suspicious_domains'].search(parsed.netloc):
                errors.append("Suspicious domain pattern")
                
            # Check against known scam domains
            if domain_info.domain in self.scam_db['blacklisted_domains']:
                errors.append("Blacklisted domain")
                
            # Check for malicious file extensions
            if self.patterns['malicious_ext'].search(parsed.path):
                errors.append("Potentially malicious file extension")
                
            # Check for IP addresses (less trustworthy)
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain_info.domain):
                errors.append("URL uses IP address instead of domain")
                
        except Exception as e:
            errors.append(f"URL validation error: {str(e)}")
            
        return (len(errors) == 0, errors)

    def validate_content(self, airdrop: Dict) -> Tuple[bool, List[str]]:
        """Content-based validation and scam detection"""
        errors = []
        
        # Name validation
        if self.patterns['scam_phrases'].search(airdrop['name']):
            errors.append("Name contains scam-like phrases")
            
        # Check against known scam patterns
        for pattern in self.scam_db['known_scam_words']:
            if pattern.lower() in airdrop['name'].lower():
                errors.append(f"Name matches known scam pattern: {pattern}")
                
        # Cryptocurrency address validation
        if 'address' in airdrop:
            if not (self.patterns['eth_address'].match(airdrop['address']) or 
                   self.patterns['btc_address'].match(airdrop['address'])):
                errors.append("Invalid cryptocurrency address format")
                
        # Metadata validation
        if 'metadata' in airdrop:
            if isinstance(airdrop['metadata'], dict):
                if 'value' in airdrop['metadata']:
                    if not re.match(r'^\$?\d+(,\d+)*(\.\d+)?$', str(airdrop['metadata']['value'])):
                        errors.append("Invalid value format in metadata")
            
        return (len(errors) == 0, errors)

    def validate_temporal(self, airdrop: Dict) -> Tuple[bool, List[str]]:
        """Time-based validation"""
        errors = []
        
        try:
            # Check scraped_at timestamp
            scraped_time = datetime.fromisoformat(airdrop['scraped_at'])
            if scraped_time > datetime.utcnow() + timedelta(hours=1):
                errors.append("Invalid future timestamp")
                
            if scraped_time < datetime.utcnow() - timedelta(days=30):
                errors.append("Data too old (over 30 days)")
                
            # Check end date if exists
            if 'metadata' in airdrop and 'end_date' in airdrop['metadata']:
                end_date = airdrop['metadata']['end_date']
                if isinstance(end_date, str):
                    if re.match(r'(expired|ended)', end_date, re.IGNORECASE):
                        errors.append("Airdrop has already ended")
                        
        except (ValueError, TypeError) as e:
            errors.append(f"Temporal validation error: {str(e)}")
            
        return (len(errors) == 0, errors)

    def calculate_reputation_score(self, airdrop: Dict) -> float:
        """Calculate a reputation score (0-1) for the airdrop"""
        score = 1.0
        
        # Penalize for each validation error
        _, structure_errors = self.validate_structure(airdrop)
        _, url_errors = self.validate_url(airdrop['link'])
        _, content_errors = self.validate_content(airdrop)
        
        total_errors = len(structure_errors + url_errors + content_errors)
        score -= total_errors * 0.1
        
        # Bonus for HTTPS
        if airdrop['link'].startswith('https://'):
            score += 0.1
            
        # Penalize new domains
        domain_age = self._get_domain_age(airdrop['link'])
        if domain_age < self.reputation_thresholds['age_days']:
            score -= 0.2
            
        return max(0.0, min(1.0, score))

    def _get_domain_age(self, url: str) -> int:
        """Mock function for domain age check (replace with actual WHOIS)"""
        return 365  # Placeholder - implement actual WHOIS lookup

    def full_validation(self, airdrop: Dict) -> Dict:
        """Comprehensive validation pipeline"""
        validation_result = {
            'is_valid': False,
            'score': 0.0,
            'warnings': [],
            'errors': [],
            'metadata': {
                'validation_time': datetime.utcnow().isoformat(),
                'validator_version': '2.1.0'
            }
        }
        
        # Run all validations
        structure_ok, structure_errors = self.validate_structure(airdrop)
        url_ok, url_errors = self.validate_url(airdrop['link'])
        content_ok, content_errors = self.validate_content(airdrop)
        temporal_ok, temporal_errors = self.validate_temporal(airdrop)
        
        # Aggregate results
        validation_result['errors'].extend(structure_errors)
        validation_result['errors'].extend(url_errors)
        validation_result['errors'].extend(content_errors)
        validation_result['errors'].extend(temporal_errors)
        
        # Calculate final validity
        validation_result['is_valid'] = all([
            structure_ok, 
            url_ok, 
            content_ok, 
            temporal_ok
        ])
        
        # Calculate reputation score
        validation_result['score'] = self.calculate_reputation_score(airdrop)
        
        # Generate warnings for borderline cases
        if 0.5 <= validation_result['score'] < 0.7:
            validation_result['warnings'].append("Borderline reputation score")
            
        return validation_result

    def validate_batch(self, airdrops: List[Dict], 
                      max_workers: int = 4) -> Dict[str, Dict]:
        """Parallel batch validation"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.full_validation, airdrop): airdrop['name']
                for airdrop in airdrops
            }
            
            for future in futures:
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as e:
                    logger.error(f"Validation failed for {name}: {str(e)}")
                    results[name] = {
                        'is_valid': False,
                        'errors': [f"Validation process failed: {str(e)}"]
                    }
                    
        return results

    def generate_report(self, validation_results: Dict[str, Dict]) -> str:
        """Generate human-readable validation report"""
        report = []
        valid_count = sum(1 for r in validation_results.values() if r['is_valid'])
        
        report.append(f"Validation Report - {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        report.append(f"Total Airdrops: {len(validation_results)}")
        report.append(f"Valid Airdrops: {valid_count} ({valid_count/len(validation_results):.1%})")
        report.append("\nDetailed Results:")
        
        for name, result in validation_results.items():
            status = "✅ VALID" if result['is_valid'] else "❌ INVALID"
            report.append(f"\n{status} - {name} (Score: {result['score']:.2f})")
            
            if result['errors']:
                report.append("  Errors:")
                for error in result['errors']:
                    report.append(f"    - {error}")
                    
            if result['warnings']:
                report.append("  Warnings:")
                for warning in result['warnings']:
                    report.append(f"    - {warning}")
                    
        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', default='sources.json',
                       help='Input JSON file with airdrops')
    parser.add_argument('--output', default='validated.json',
                       help='Output file for validation results')
    parser.add_argument('--report', action='store_true',
                       help='Generate human-readable report')
    args = parser.parse_args()
    
    validator = AirdropValidator()
    
    try:
        with open(args.input) as f:
            airdrops = json.load(f).get('data', [])
            
        results = validator.validate_batch(airdrops)
        
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
            
        if args.report:
            print(validator.generate_report(results))
            
        logger.info(f"Validation complete. Results saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Validation failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()