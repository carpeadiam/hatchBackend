import os
import re
import ast
import hashlib
import requests
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, Counter
from functools import lru_cache
import json
import base64

from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest
import numpy as np
from datasketch import MinHashLSH, MinHash

# Configuration
class Config:
    GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
    CACHE_TTL = 7200  # 2 hours (increased for Azure)
    MAX_FILES_TO_ANALYZE = 30  # Reduced for better token management
    MAX_COMMITS_TO_ANALYZE = 50  # Reduced for better token management
    RATE_LIMIT_DELAY = 2.0  # Increased delay for better token conservation
    
    # Inter-repo search limits for token conservation
    MAX_SEARCH_QUERIES = 8  # Maximum search queries per analysis
    MAX_RESULTS_PER_QUERY = 5  # Maximum results to process per query
    SNIPPET_MIN_LENGTH = 30  # Minimum snippet length for search
    SNIPPET_MAX_LENGTH = 150  # Maximum snippet length for search
    
    # Scoring weights
    COMMIT_WEIGHT = 0.3
    INTRA_REPO_WEIGHT = 0.4
    INTER_REPO_WEIGHT = 0.3
    
    # Azure deployment settings
    AZURE_FRIENDLY = True
    TIMEOUT_SECONDS = 120  # 2 minutes timeout for Azure

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Global cache and rate limiter
_cache = {}
_last_api_call = 0

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def rate_limit():
    """Enhanced rate limiter with exponential backoff for API calls"""
    global _last_api_call
    now = time.time()
    delay = Config.RATE_LIMIT_DELAY
    
    # Add jitter to avoid thundering herd
    import random
    jitter = random.uniform(0.1, 0.5)
    delay += jitter
    
    if now - _last_api_call < delay:
        sleep_time = delay - (now - _last_api_call)
        time.sleep(sleep_time)
    _last_api_call = time.time()

def cache_get(key: str) -> Optional[Any]:
    """Get item from cache if not expired"""
    if key in _cache:
        value, timestamp = _cache[key]
        if time.time() - timestamp < Config.CACHE_TTL:
            return value
        del _cache[key]
    return None

def cache_set(key: str, value: Any):
    """Set item in cache with timestamp"""
    _cache[key] = (value, time.time())

def parse_github_url(url: str) -> Tuple[str, str]:
    """Extract owner and repo from GitHub URL"""
    patterns = [
        r'github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$',
        r'github\.com/([^/]+)/([^/]+)/.*'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1), match.group(2)
    
    raise ValueError("Invalid GitHub URL format")

# ============================================================================
# CODE NORMALIZATION
# ============================================================================

class CodeNormalizer:
    """Normalizes code for similarity comparison"""
    
    @staticmethod
    def remove_comments(code: str, language: str = 'python') -> str:
        """Remove comments based on language"""
        if language in ['python', 'py']:
            # Remove # comments
            code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
            # Remove """ and ''' strings (docstrings)
            code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)
            code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)
        elif language in ['javascript', 'js', 'java', 'cpp', 'c']:
            # Remove // comments
            code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
            # Remove /* */ comments
            code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        
        return code
    
    @staticmethod
    def normalize_whitespace(code: str) -> str:
        """Normalize whitespace and indentation"""
        lines = [line.strip() for line in code.split('\n')]
        return '\n'.join(line for line in lines if line)
    
    @staticmethod
    def normalize_variables(code: str) -> str:
        """Replace variable names with generic placeholders"""
        # Simple variable normalization - replace identifiers
        # This is a basic implementation; AST-based would be better
        words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', code)
        var_map = {}
        var_counter = 0
        
        normalized = code
        for word in set(words):
            if word not in ['def', 'class', 'if', 'else', 'for', 'while', 'try', 'except',
                           'import', 'from', 'return', 'print', 'len', 'range', 'str', 'int']:
                if word not in var_map:
                    var_map[word] = f'var{var_counter}'
                    var_counter += 1
                normalized = re.sub(r'\b' + re.escape(word) + r'\b', var_map[word], normalized)
        
        return normalized
    
    @classmethod
    def normalize_code(cls, code: str, language: str = 'python') -> str:
        """Full code normalization pipeline"""
        code = cls.remove_comments(code, language)
        code = cls.normalize_whitespace(code)
        code = cls.normalize_variables(code)
        return code

# ============================================================================
# GITHUB API SERVICE
# ============================================================================

class GitHubService:
    """GitHub API interaction service"""
    
    def __init__(self, token: str):
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {token}" if token else "",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "PlagiarismChecker/1.0"
        }
    
    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """Make rate-limited API request with enhanced error handling"""
        rate_limit()
        cache_key = f"github_{endpoint}_{hash(str(params))}"
        
        # Check cache first
        cached = cache_get(cache_key)
        if cached:
            return cached
        
        url = f"{self.base_url}/{endpoint}"
        try:
            response = requests.get(
                url, 
                headers=self.headers, 
                params=params or {}, 
                timeout=Config.TIMEOUT_SECONDS if hasattr(Config, 'TIMEOUT_SECONDS') else 30
            )
            
            # Enhanced rate limit handling
            if response.status_code == 403:
                remaining = response.headers.get('X-RateLimit-Remaining', '0')
                reset_time = response.headers.get('X-RateLimit-Reset', '0')
                print(f"Rate limit hit. Remaining: {remaining}, Reset: {reset_time}")
                
                # If we're close to rate limit, add exponential backoff
                if int(remaining) < 10:
                    backoff_time = min(60, 2 ** (10 - int(remaining)))  # Max 60 seconds
                    print(f"Low rate limit remaining, backing off for {backoff_time} seconds")
                    time.sleep(backoff_time)
                
                raise Exception(f"GitHub API rate limit exceeded. Remaining: {remaining}")
            elif response.status_code == 422:
                print(f"Search query validation failed: {response.text}")
                return {"items": []} if "search" in endpoint else {}
            elif response.status_code != 200:
                print(f"GitHub API error {response.status_code}: {response.text}")
                raise Exception(f"GitHub API error: {response.status_code}")
            
            data = response.json()
            cache_set(cache_key, data)
            return data
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return {"items": []} if "search" in endpoint else {}
    
    def get_repository_info(self, owner: str, repo: str) -> Dict:
        """Get basic repository information"""
        return self._make_request(f"repos/{owner}/{repo}")
    
    def get_commits(self, owner: str, repo: str, limit: int = 100) -> List[Dict]:
        """Get repository commits"""
        params = {"per_page": min(limit, 100)}
        commits = self._make_request(f"repos/{owner}/{repo}/commits", params)
        return commits[:limit] if isinstance(commits, list) else []
    
    def get_file_content(self, owner: str, repo: str, path: str, ref: str = "main") -> Optional[str]:
        """Get file content from repository with enhanced error handling"""
        print(f"Attempting to get content for file: {path}")
        
        # Try different branch names
        branches_to_try = [ref, "main", "master"]
        if ref not in branches_to_try:
            branches_to_try.insert(0, ref)
        
        for branch in branches_to_try:
            try:
                print(f"Trying to get {path} from branch: {branch}")
                data = self._make_request(f"repos/{owner}/{repo}/contents/{path}", {"ref": branch})
                
                if data and data.get("encoding") == "base64":
                    try:
                        content = base64.b64decode(data["content"]).decode('utf-8', errors='ignore')
                        print(f"Successfully retrieved content for {path} from {branch} ({len(content)} chars)")
                        return content
                    except Exception as decode_error:
                        print(f"Failed to decode content for {path}: {decode_error}")
                        continue
                else:
                    print(f"No valid content data for {path} from {branch}")
                    
            except Exception as e:
                print(f"Failed to get file content for {path} from {branch}: {e}")
                continue
        
        print(f"Failed to get content for {path} from any branch")
        return None
    
    def get_repository_files(self, owner: str, repo: str, limit: int = 50) -> List[Dict]:
        """Get repository file tree with enhanced error handling and debugging"""
        try:
            print(f"Attempting to get repository files for {owner}/{repo}")
            
            # Try main branch first, then master, then default branch
            branches_to_try = ["main", "master"]
            tree_data = None
            
            # First, get repository info to find default branch
            try:
                repo_info = self._make_request(f"repos/{owner}/{repo}")
                default_branch = repo_info.get("default_branch", "main")
                if default_branch not in branches_to_try:
                    branches_to_try.insert(0, default_branch)
                print(f"Repository default branch: {default_branch}")
            except Exception as e:
                print(f"Could not get repo info: {e}")
            
            # Try each branch
            for branch in branches_to_try:
                try:
                    print(f"Trying branch: {branch}")
                    tree_data = self._make_request(f"repos/{owner}/{repo}/git/trees/{branch}", {"recursive": "1"})
                    if tree_data and "tree" in tree_data:
                        print(f"Successfully retrieved tree from branch: {branch}")
                        break
                    else:
                        print(f"No tree data from branch: {branch}")
                except Exception as e:
                    print(f"Failed to get tree from branch {branch}: {e}")
                    continue
            
            if not tree_data or "tree" not in tree_data:
                print("Failed to retrieve repository tree from any branch")
                return []
            
            print(f"Total items in repository tree: {len(tree_data.get('tree', []))}")
            
            files = []
            for item in tree_data.get("tree", []):
                if item["type"] == "blob":
                    print(f"Found blob: {item['path']} (size: {item.get('size', 'unknown')})")
                    
                    if self._is_code_file(item["path"]):
                        # Add size information if available
                        file_info = {
                            "path": item["path"],
                            "sha": item["sha"],
                            "size": item.get("size", 0),
                            "url": item.get("url", "")
                        }
                        files.append(file_info)
                        print(f"Added code file: {item['path']} (size: {item.get('size', 'unknown')})")
                    else:
                        print(f"Skipped non-code file: {item['path']}")
                    
                    if len(files) >= limit:
                        break
            
            print(f"Found {len(files)} code files (limit: {limit})")
            return files
            
        except Exception as e:
            print(f"Failed to get repository files: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def search_code(self, query: str, language: str = None, max_results: int = None) -> List[Dict]:
        """Search for code across GitHub with enhanced filtering"""
        # Clean and validate query
        query = query.strip()
        min_length = getattr(Config, 'SNIPPET_MIN_LENGTH', 30)
        max_length = getattr(Config, 'SNIPPET_MAX_LENGTH', 150)
        
        if len(query) < min_length:
            print(f"Query too short ({len(query)} < {min_length}): {query[:50]}...")
            return []
        
        # Truncate if too long
        if len(query) > max_length:
            query = query[:max_length]
        
        # Enhanced query cleaning for better results
        query = re.sub(r'[^\w\s\(\)\{\}\[\]\.,;:]', ' ', query)
        query = re.sub(r'\s+', ' ', query).strip()
        
        if len(query) < min_length:
            return []
        
        # Build search query with better escaping
        search_query = f'"{query}"'
        
        if language:
            search_query += f" language:{language}"
        
        # Add filters to improve result quality
        search_query += " NOT filename:README NOT filename:LICENSE"
        
        max_results = max_results or getattr(Config, 'MAX_RESULTS_PER_QUERY', 5)
        params = {"q": search_query, "per_page": max_results}
        
        try:
            print(f"Searching GitHub for: {search_query[:100]}...")
            result = self._make_request("search/code", params)
            items = result.get("items", [])
            print(f"Found {len(items)} results for query")
            return items[:max_results]  # Ensure we don't exceed our limit
        except Exception as e:
            print(f"Search failed for query '{query[:50]}...': {e}")
            return []
    
    @staticmethod
    def _is_code_file(path: str) -> bool:
        """Check if file is a code file based on extension with enhanced detection"""
        path_lower = path.lower()
        
        # Code file extensions (expanded list)
        code_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.cc', '.cxx',
            '.h', '.hpp', '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala',
            '.m', '.mm', '.pl', '.sh', '.ps1', '.r', '.matlab', '.sql', '.html', '.css',
            '.scss', '.sass', '.less', '.vue', '.dart', '.lua', '.perl', '.asm', '.s',
            '.yml', '.yaml', '.xml', '.json', '.md', '.txt'  # Include config and text files too
        }
        
        # Check file extension
        has_code_ext = any(path_lower.endswith(ext) for ext in code_extensions)
        
        # Also include files without extensions that might be scripts or important files
        if not has_code_ext and '.' not in path.split('/')[-1]:  # No extension
            # Common script names and important files without extensions
            filename = path.split('/')[-1].lower()
            important_files = {
                'dockerfile', 'makefile', 'rakefile', 'gemfile', 'vagrantfile',
                'procfile', 'gruntfile', 'gulpfile', 'webpack', 'readme', 'license',
                'changelog', 'contributing', 'authors', 'install', 'usage'
            }
            has_code_ext = filename in important_files
            
            # If it's README, we definitely want to include it
            if filename == 'readme':
                has_code_ext = True
        
        # Exclude certain directories but be less restrictive
        exclude_patterns = [
            'node_modules/', '.git/', '__pycache__/', '.vscode/', '.idea/',
            'dist/', 'build/', 'target/', 'bin/', 'obj/', 'out/', '.next/',
            'coverage/', '.nyc_output/', 'vendor/', 'packages/'
        ]
        
        # Only exclude if it's clearly in an excluded directory
        is_excluded = any(f'/{pattern}' in f'/{path_lower}' or path_lower.startswith(pattern) for pattern in exclude_patterns)
        
        result = has_code_ext and not is_excluded
        
        if result:
            print(f"✅ Accepted code file: {path}")
        elif has_code_ext and is_excluded:
            print(f"❌ Excluded code file: {path} (matches exclusion pattern)")
        else:
            print(f"⏭️  Skipped file: {path} (not recognized as code)")
        
        return result

# ============================================================================
# COMMIT ANALYSIS
# ============================================================================

class CommitAnalyzer:
    """Analyzes commit patterns for suspicious behavior"""
    
    def __init__(self, github_service: GitHubService):
        self.github = github_service
    
    def analyze_commits(self, owner: str, repo: str) -> Dict:
        """Analyze commit patterns for plagiarism indicators"""
        commits = self.github.get_commits(owner, repo, Config.MAX_COMMITS_TO_ANALYZE)
        
        if not commits:
            return {"score": 0, "indicators": [], "commit_count": 0}
        
        indicators = []
        score = 0
        
        # Analyze commit timing
        timing_score = self._analyze_commit_timing(commits)
        score += timing_score
        if timing_score > 50:
            indicators.append("Suspicious commit timing patterns")
        
        # Analyze commit messages
        message_score = self._analyze_commit_messages(commits)
        score += message_score
        if message_score > 50:
            indicators.append("Generic or suspicious commit messages")
        
        # Analyze commit sizes - simplified
        size_score = self._analyze_commit_sizes(commits)
        score += size_score
        if size_score > 50:
            indicators.append("Unusual commit size patterns")
        
        # Analyze author patterns
        author_score = self._analyze_authors(commits)
        score += author_score
        if author_score > 50:
            indicators.append("Suspicious author patterns")
        
        return {
            "score": min(score / 4, 100),  # Average of all scores
            "indicators": indicators,
            "commit_count": len(commits),
            "details": {
                "timing_score": timing_score,
                "message_score": message_score,
                "size_score": size_score,
                "author_score": author_score
            }
        }
    
    def _analyze_commit_timing(self, commits: List[Dict]) -> float:
        """Analyze commit timing patterns"""
        if len(commits) < 2:
            return 0
        
        timestamps = []
        for commit in commits:
            try:
                timestamp = datetime.fromisoformat(commit["commit"]["author"]["date"].replace('Z', '+00:00'))
                timestamps.append(timestamp)
            except:
                continue
        
        if len(timestamps) < 2:
            return 0
        
        # Check for bulk commits (many commits in short time)
        time_diffs = []
        for i in range(1, len(timestamps)):
            diff = (timestamps[i-1] - timestamps[i]).total_seconds() / 60  # minutes
            time_diffs.append(diff)
        
        # Score based on how many commits were made in rapid succession
        rapid_commits = sum(1 for diff in time_diffs if diff < 5)  # < 5 minutes apart
        bulk_ratio = rapid_commits / len(time_diffs) if time_diffs else 0
        
        return min(bulk_ratio * 100, 100)
    
    def _analyze_commit_messages(self, commits: List[Dict]) -> float:
        """Analyze commit message quality"""
        messages = [commit["commit"]["message"].lower().strip() for commit in commits]
        
        # Generic message patterns
        generic_patterns = [
            r'^(initial commit|first commit)$',
            r'^(update|updated)$',
            r'^(fix|fixed)$',
            r'^(commit|new)$',
            r'^[a-zA-Z]$',  # Single character
            r'^\d+$',       # Just numbers
        ]
        
        generic_count = 0
        for message in messages:
            for pattern in generic_patterns:
                if re.match(pattern, message):
                    generic_count += 1
                    break
        
        # Check for duplicate messages
        message_counts = Counter(messages)
        duplicate_ratio = sum(count - 1 for count in message_counts.values()) / len(messages)
        
        generic_ratio = generic_count / len(messages) if messages else 0
        
        return min((generic_ratio + duplicate_ratio) * 100, 100)
    
    def _analyze_commit_sizes(self, commits: List[Dict]) -> float:
        """Analyze commit size patterns (simplified version)"""
        # Simple heuristic: if there are very few commits for a large codebase, it's suspicious
        if len(commits) < 5:
            return 70  # Suspicious: very few commits
        elif len(commits) < 10:
            return 30  # Somewhat suspicious
        else:
            return 0   # Normal
    
    def _analyze_authors(self, commits: List[Dict]) -> float:
        """Analyze author patterns"""
        authors = []
        for commit in commits:
            try:
                author = commit["commit"]["author"]["name"]
                authors.append(author)
            except:
                continue
        
        if not authors:
            return 0
        
        # Check for single author doing everything (suspicious for group projects)
        author_counts = Counter(authors)
        dominant_author_ratio = max(author_counts.values()) / len(authors)
        
        # Check for suspicious author names
        suspicious_patterns = [
            r'^user\d*$',
            r'^admin\d*$',
            r'^test\d*$',
            r'^[a-zA-Z]{1,3}\d+$',  # Very short names with numbers
        ]
        
        suspicious_authors = 0
        for author in set(authors):
            for pattern in suspicious_patterns:
                if re.match(pattern, author.lower()):
                    suspicious_authors += 1
                    break
        
        suspicious_ratio = suspicious_authors / len(set(authors)) if authors else 0
        
        # Score based on dominance and suspicious names
        score = (dominant_author_ratio * 50) + (suspicious_ratio * 50)
        return min(score, 100)

# ============================================================================
# SIMILARITY DETECTION
# ============================================================================

class SimilarityService:
    """Code similarity detection using multiple methods"""
    
    def __init__(self, github_service: GitHubService):
        self.github = github_service
        self.normalizer = CodeNormalizer()
    
    def analyze_intra_repo_similarity(self, owner: str, repo: str) -> Dict:
        """Analyze similarity within the repository with enhanced debugging"""
        print(f"Starting intra-repository analysis for {owner}/{repo}")
        
        max_files = min(Config.MAX_FILES_TO_ANALYZE, 20)  # Reasonable limit
        files = self.github.get_repository_files(owner, repo, max_files)
        
        print(f"Retrieved {len(files)} files for intra-repo analysis")
        
        if len(files) < 2:
            print(f"Not enough files for comparison: {len(files)}")
            return {"score": 0, "similar_files": [], "file_count": len(files)}
        
        # Get file contents
        file_contents = {}
        for file_info in files[:10]:  # Limit to avoid too many API calls
            content = self.github.get_file_content(owner, repo, file_info["path"])
            if content and len(content.strip()) > 50:  # Only include substantial files
                file_contents[file_info["path"]] = content
                print(f"Loaded content for {file_info['path']} ({len(content)} chars)")
            else:
                print(f"Skipped {file_info['path']} - content too small or unavailable")
        
        print(f"Loaded content for {len(file_contents)} files")
        
        if len(file_contents) < 2:
            print("Not enough files with content for comparison")
            return {"score": 0, "similar_files": [], "file_count": len(file_contents)}
        
        # Compare files for similarity
        similar_pairs = []
        file_paths = list(file_contents.keys())
        
        print(f"Comparing {len(file_paths)} files for similarity...")
        
        comparisons_made = 0
        for i in range(len(file_paths)):
            for j in range(i + 1, len(file_paths)):
                path1, path2 = file_paths[i], file_paths[j]
                
                try:
                    similarity = self._calculate_similarity(
                        file_contents[path1], 
                        file_contents[path2]
                    )
                    
                    comparisons_made += 1
                    print(f"Similarity between {path1} and {path2}: {similarity:.3f}")
                    
                    if similarity > 0.6:  # 60% similarity threshold
                        similar_pairs.append({
                            "file1": path1,
                            "file2": path2,
                            "similarity": round(similarity, 3)
                        })
                        print(f"Added similar pair: {path1} <-> {path2} ({similarity:.3f})")
                        
                except Exception as e:
                    print(f"Error comparing {path1} and {path2}: {e}")
                    continue
        
        print(f"Made {comparisons_made} comparisons, found {len(similar_pairs)} similar pairs")
        
        # Calculate score based on similar pairs
        max_possible_pairs = len(file_paths) * (len(file_paths) - 1) // 2
        similarity_ratio = len(similar_pairs) / max_possible_pairs if max_possible_pairs > 0 else 0
        
        score = min(similarity_ratio * 200, 100)  # Amplify the score
        print(f"Intra-repo similarity score: {score:.2f}%")
        
        return {
            "score": score,
            "similar_files": similar_pairs,
            "file_count": len(file_contents),
            "comparisons_made": comparisons_made
        }
    
    def analyze_inter_repo_similarity(self, owner: str, repo: str) -> Dict:
        """Analyze similarity with other repositories - ENHANCED VERSION"""
        # Inter-repo analysis with enhanced debugging
        max_files = min(10, getattr(Config, 'MAX_FILES_TO_ANALYZE', 30) // 3)
        files = self.github.get_repository_files(owner, repo, max_files)
        
        print(f"Retrieved {len(files)} files for inter-repo analysis")
        
        if not files:
            print("No files found for inter-repository analysis")
            return {"score": 0, "matches": [], "files_checked": 0, "search_attempts": 0}
        
        matches = []
        files_checked = 0
        total_search_attempts = 0
        max_search_queries = getattr(Config, 'MAX_SEARCH_QUERIES', 8)
        
        print(f"Analyzing {len(files)} files for inter-repo similarity (max {max_search_queries} searches)...")
        
        # Prioritize larger, more significant files
        prioritized_files = self._prioritize_files_for_analysis(files, owner, repo)
        
        for file_info in prioritized_files[:max_files]:  # Respect file limit
            if total_search_attempts >= max_search_queries:
                print(f"Reached maximum search queries limit ({max_search_queries})")
                break
                
            content = self.github.get_file_content(owner, repo, file_info["path"])
            if not content or len(content.strip()) < 100:  # Skip small files
                continue
            
            files_checked += 1
            print(f"Checking file: {file_info['path']} ({len(content)} chars)")
            
            # Extract high-quality snippets for searching
            snippets = self._extract_high_quality_snippets(content, file_info["path"])
            
            # Limit snippets per file to conserve API calls
            max_snippets_per_file = max(1, max_search_queries // max_files)
            
            for snippet in snippets[:max_snippets_per_file]:
                if total_search_attempts >= max_search_queries:
                    break
                    
                if not self._is_snippet_worth_searching(snippet):
                    continue
                
                total_search_attempts += 1
                
                # Determine language from file extension
                language = self._get_language_from_path(file_info["path"])
                
                # Search for similar code with conservative limits
                search_results = self.github.search_code(
                    snippet, 
                    language, 
                    max_results=getattr(Config, 'MAX_RESULTS_PER_QUERY', 5)
                )
                
                # Process results with quality filtering
                for result in search_results:
                    result_repo = f"{result['repository']['owner']['login']}/{result['repository']['name']}"
                    if result_repo != f"{owner}/{repo}":
                        # Calculate similarity confidence
                        confidence = self._calculate_match_confidence(snippet, result)
                        
                        match_data = {
                            "file": file_info["path"],
                            "match_repo": result_repo,
                            "match_file": result["path"],
                            "snippet": snippet[:100] + "..." if len(snippet) > 100 else snippet,
                            "match_url": result.get("html_url", ""),
                            "confidence": confidence,
                            "language": language or "unknown"
                        }
                        matches.append(match_data)
                        print(f"Found match in {result_repo} (confidence: {confidence:.2f})")
                
                # Stop if we have sufficient high-quality matches
                high_conf_matches = [m for m in matches if m.get('confidence', 0) > 0.7]
                if len(high_conf_matches) >= 3:
                    print("Found sufficient high-confidence matches, stopping search")
                    break
            
            # Stop file processing if we have enough evidence
            if len(matches) >= 5:
                break
        
        # Enhanced scoring based on match quality
        score = self._calculate_inter_repo_score(matches, files_checked, total_search_attempts)
        
        print(f"Inter-repo analysis complete: {len(matches)} matches found from {files_checked} files, {total_search_attempts} searches")
        
        return {
            "score": score,
            "matches": matches[:10],  # Limit returned matches
            "files_checked": files_checked,
            "search_attempts": total_search_attempts,
            "high_confidence_matches": len([m for m in matches if m.get('confidence', 0) > 0.7])
        }
    
    def _extract_high_quality_snippets(self, content: str, file_path: str) -> List[str]:
        """Extract high-quality code snippets optimized for searching"""
        snippets = []
        
        # Normalize and clean content
        normalized = self.normalizer.normalize_code(content)
        lines = [line.strip() for line in normalized.split('\n') if line.strip()]
        
        if len(lines) < 3:
            return []
        
        # Extract function/class definitions with context
        function_patterns = [
            r'^\s*(def|class|function|public\s+class|private\s+class)\s+\w+',
            r'^\s*(public|private|protected)\s+\w+\s+\w+\s*\(',
            r'^\s*\w+\s*=\s*function\s*\(',
        ]
        
        for i, line in enumerate(lines):
            for pattern in function_patterns:
                if re.match(pattern, line) and len(line) > 20:
                    # Include some context (2-3 lines)
                    context_start = max(0, i)
                    context_end = min(len(lines), i + 3)
                    context_block = '\n'.join(lines[context_start:context_end])
                    if len(context_block) >= 40:
                        snippets.append(context_block)
                    break
        
        # Extract algorithm-like blocks (loops, conditionals with logic)
        for i in range(len(lines) - 2):
            if re.match(r'^\s*(for|while|if)\s+', lines[i]):
                block = '\n'.join(lines[i:i+3])
                if len(block) > 50 and self._contains_meaningful_logic(block):
                    snippets.append(block)
        
        # Extract unique computational or algorithmic lines
        for line in lines:
            if (len(line) > 30 and 
                self._is_algorithmic_line(line) and 
                not self._is_common_line(line)):
                snippets.append(line)
        
        # Remove duplicates and prioritize by quality
        unique_snippets = list(set(snippets))
        prioritized = self._prioritize_snippets_by_quality(unique_snippets, file_path)
        
        return prioritized[:3]  # Return top 3 quality snippets
    
    def _prioritize_files_for_analysis(self, files: List[Dict], owner: str, repo: str) -> List[Dict]:
        """Prioritize files based on their likelihood to contain unique code"""
        def file_priority(file_info):
            path = file_info["path"].lower()
            score = 0
            
            # Prefer source files over config/test files
            if any(path.endswith(ext) for ext in ['.py', '.js', '.java', '.cpp', '.c']):
                score += 10
            
            # Avoid test, config, and documentation files
            if any(keyword in path for keyword in ['test', 'spec', 'config', 'readme', 'doc']):
                score -= 5
            
            # Prefer files in src, lib, app directories
            if any(keyword in path for keyword in ['src/', 'lib/', 'app/', 'core/']):
                score += 5
            
            # Prefer larger files (more content to analyze)
            score += min(file_info.get("size", 0) / 1000, 5)  # Max 5 points for size
            
            return score
        
        return sorted(files, key=file_priority, reverse=True)
    
    def _is_snippet_worth_searching(self, snippet: str) -> bool:
        """Determine if a snippet is worth using for GitHub search"""
        if not snippet or len(snippet.strip()) < getattr(Config, 'SNIPPET_MIN_LENGTH', 30):
            return False
        
        # Check if snippet has meaningful content
        lines = snippet.split('\n')
        meaningful_lines = 0
        
        for line in lines:
            line = line.strip()
            if (len(line) > 10 and 
                not re.match(r'^[{}()\[\]\s]*$', line) and  # Not just brackets
                not re.match(r'^(import|from|#|//)', line)):   # Not imports or comments
                meaningful_lines += 1
        
        return meaningful_lines >= 2
    
    def _contains_meaningful_logic(self, block: str) -> bool:
        """Check if code block contains meaningful algorithmic logic"""
        # Look for operators, function calls, assignments
        logic_patterns = [
            r'[+\-*/=<>!&|]',  # Operators
            r'\w+\s*\(',       # Function calls
            r'\w+\s*\[',       # Array access
            r'\.(\w+)',       # Method calls
        ]
        
        return any(re.search(pattern, block) for pattern in logic_patterns)
    
    def _is_algorithmic_line(self, line: str) -> bool:
        """Check if line contains algorithmic content"""
        algorithmic_patterns = [
            r'\w+\s*=\s*\w+.*[+\-*/]',  # Calculations
            r'(sort|filter|map|reduce)\s*\(',  # Data processing
            r'(if|while|for)\s+.*[<>=!]',  # Control flow with conditions
            r'\w+\.(append|push|pop|insert)',  # Data structure operations
        ]
        
        return any(re.search(pattern, line) for pattern in algorithmic_patterns)
    
    def _prioritize_snippets_by_quality(self, snippets: List[str], file_path: str) -> List[str]:
        """Prioritize snippets by their uniqueness and search potential"""
        def snippet_quality(snippet):
            score = 0
            
            # Longer snippets are generally more unique
            score += min(len(snippet) / 20, 5)
            
            # Prefer snippets with specific identifiers
            if re.search(r'\w{6,}', snippet):  # Long identifiers
                score += 3
            
            # Prefer snippets with multiple operators or function calls
            operators = len(re.findall(r'[+\-*/=<>!&|]', snippet))
            score += min(operators, 3)
            
            # Avoid overly generic snippets
            if re.search(r'^\s*(print|console\.log|return|if\s+True)', snippet):
                score -= 2
            
            return score
        
        return sorted(snippets, key=snippet_quality, reverse=True)
    
    def _calculate_match_confidence(self, snippet: str, result: Dict) -> float:
        """Calculate confidence score for a search result match"""
        confidence = 0.5  # Base confidence
        
        # Higher confidence for longer snippets
        if len(snippet) > 80:
            confidence += 0.2
        
        # Higher confidence if repository has similar name/topic
        repo_name = result.get('repository', {}).get('name', '').lower()
        if any(keyword in repo_name for keyword in ['project', 'assignment', 'homework']):
            confidence += 0.3
        
        # Higher confidence for exact file type matches
        result_path = result.get('path', '').lower()
        if result_path.split('.')[-1] == snippet.split('.')[-1] if '.' in result_path else False:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _calculate_inter_repo_score(self, matches: List[Dict], files_checked: int, search_attempts: int) -> float:
        """Calculate enhanced inter-repository similarity score"""
        if not matches or files_checked == 0:
            return 0.0
        
        # Base score from match ratio
        match_ratio = len(matches) / max(files_checked, 1)
        base_score = min(match_ratio * 100, 80)  # Cap at 80 for base
        
        # Boost for high-confidence matches
        high_conf_matches = [m for m in matches if m.get('confidence', 0) > 0.7]
        if high_conf_matches:
            confidence_boost = min(len(high_conf_matches) * 15, 30)
            base_score += confidence_boost
        
        # Boost for multiple matches in same repository (suspicious)
        repo_counts = {}
        for match in matches:
            repo = match.get('match_repo', '')
            repo_counts[repo] = repo_counts.get(repo, 0) + 1
        
        if any(count > 1 for count in repo_counts.values()):
            base_score += 20  # Significant boost for same-repo multiple matches
        
        return min(base_score, 100.0)
    
    def _get_language_from_path(self, path: str) -> Optional[str]:
        """Get programming language from file path"""
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.java': 'java',
            '.cpp': 'cpp',
            '.c': 'c',
            '.cs': 'csharp',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go'
        }
        
        for ext, lang in ext_map.items():
            if path.endswith(ext):
                return lang
        return None
    
    def _calculate_similarity(self, code1: str, code2: str) -> float:
        """Calculate similarity between two code snippets"""
        # Normalize both code snippets
        norm1 = self.normalizer.normalize_code(code1)
        norm2 = self.normalizer.normalize_code(code2)
        
        if not norm1 or not norm2:
            return 0.0
        
        # Use MinHash for similarity
        mh1 = MinHash(num_perm=128)
        mh2 = MinHash(num_perm=128)
        
        # Create shingles (n-grams) from normalized code
        shingles1 = self._create_shingles(norm1, 3)
        shingles2 = self._create_shingles(norm2, 3)
        
        if not shingles1 or not shingles2:
            return 0.0
        
        for shingle in shingles1:
            mh1.update(shingle.encode('utf-8'))
        
        for shingle in shingles2:
            mh2.update(shingle.encode('utf-8'))
        
        return mh1.jaccard(mh2)
    
    def _create_shingles(self, text: str, k: int) -> List[str]:
        """Create k-shingles from text"""
        text = re.sub(r'\s+', ' ', text.strip())
        return [text[i:i+k] for i in range(len(text) - k + 1)]
    
    def _is_common_block(self, block: str) -> bool:
        """Check if a code block is too common to be useful"""
        common_patterns = [
            r'^\s*(import|from)\s+',
            r'^\s*(def|class)\s+\w+',
            r'^\s*(if|for|while)\s*',
            r'^\s*(return|print)\s*',
            r'^\s*[{}()\[\]]+\s*$',
        ]
        
        lines = block.split('\n')
        common_count = 0
        for line in lines:
            for pattern in common_patterns:
                if re.match(pattern, line.lower()):
                    common_count += 1
                    break
        
        return common_count >= len(lines) * 0.8  # 80% of lines are common
    
    def _is_common_line(self, line: str) -> bool:
        """Check if a line is too common to be useful for search"""
        common_patterns = [
            r'^(import|from)\s+',
            r'^(def|class)\s+\w+',
            r'^(if|for|while|try)\s*',
            r'^(return|print|pass)$',
            r'^\s*[{}()\[\]]+\s*$',
            r'^\s*(#|//|\*)',  # Comments
        ]
        
        return any(re.match(pattern, line.lower()) for pattern in common_patterns)

# ============================================================================
# SCORING SERVICE
# ============================================================================

class ScoringService:
    """Combines all analysis results into a final plagiarism score"""
    
    def calculate_plagiarism_score(self, commit_analysis: Dict, 
                                 intra_repo_analysis: Dict, 
                                 inter_repo_analysis: Dict) -> Dict:
        """Calculate final plagiarism score with enhanced weighting"""
        
        # Extract individual scores
        commit_score = commit_analysis.get("score", 0)
        intra_score = intra_repo_analysis.get("score", 0)
        inter_score = inter_repo_analysis.get("score", 0)
        
        print(f"Component scores - Commit: {commit_score}, Intra: {intra_score}, Inter: {inter_score}")
        
        # Calculate weighted final score
        final_score = (
            commit_score * Config.COMMIT_WEIGHT +
            intra_score * Config.INTRA_REPO_WEIGHT +
            inter_score * Config.INTER_REPO_WEIGHT
        )
        
        # Enhanced boosting based on evidence quality
        matches = inter_repo_analysis.get("matches", [])
        high_conf_matches = inter_repo_analysis.get("high_confidence_matches", 0)
        
        if high_conf_matches > 0:
            final_score = max(final_score, 50 + (high_conf_matches * 10))  # Significant boost for high confidence
        elif matches:
            final_score = max(final_score, 35 + (len(matches) * 5))  # Moderate boost for any matches
        
        if intra_repo_analysis.get("similar_files"):
            similar_count = len(intra_repo_analysis["similar_files"])
            final_score = max(final_score, 25 + (similar_count * 5))  # Boost for internal similarity
        
        # Cap the maximum score
        final_score = min(final_score, 100)
        
        # Determine risk level with more nuanced thresholds
        if final_score >= 75:
            risk_level = "HIGH"
        elif final_score >= 50:
            risk_level = "MEDIUM"
        elif final_score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        # Collect all indicators with enhanced details
        all_indicators = []
        all_indicators.extend(commit_analysis.get("indicators", []))
        
        if intra_repo_analysis.get("similar_files"):
            count = len(intra_repo_analysis["similar_files"])
            all_indicators.append(f"Found {count} similar file pairs within repository")
        
        if matches:
            total_matches = len(matches)
            high_conf = high_conf_matches
            if high_conf > 0:
                all_indicators.append(f"Found {total_matches} potential matches in other repositories ({high_conf} high-confidence)")
            else:
                all_indicators.append(f"Found {total_matches} potential matches in other repositories")
        
        # Add search efficiency indicator
        search_attempts = inter_repo_analysis.get("search_attempts", 0)
        files_checked = inter_repo_analysis.get("files_checked", 0)
        if search_attempts > 0:
            all_indicators.append(f"Analyzed {files_checked} files with {search_attempts} search queries")
        
        return {
            "final_score": round(final_score, 2),
            "risk_level": risk_level,
            "component_scores": {
                "commit_patterns": round(commit_score, 2),
                "intra_repository_similarity": round(intra_score, 2),
                "inter_repository_similarity": round(inter_score, 2)
            },
            "indicators": all_indicators,
            "confidence": self._calculate_confidence(commit_analysis, intra_repo_analysis, inter_repo_analysis),
            "analysis_quality": self._assess_analysis_quality(commit_analysis, intra_repo_analysis, inter_repo_analysis)
        }
    
    def _calculate_confidence(self, commit_analysis: Dict, 
                            intra_repo_analysis: Dict, 
                            inter_repo_analysis: Dict) -> str:
        """Calculate confidence level based on available data and quality"""
        
        commit_count = commit_analysis.get("commit_count", 0)
        file_count = intra_repo_analysis.get("file_count", 0)
        files_checked = inter_repo_analysis.get("files_checked", 0)
        search_attempts = inter_repo_analysis.get("search_attempts", 0)
        high_conf_matches = inter_repo_analysis.get("high_confidence_matches", 0)
        
        # Enhanced confidence calculation
        confidence_score = 0
        
        # Commit analysis quality
        if commit_count >= 20:
            confidence_score += 30
        elif commit_count >= 10:
            confidence_score += 20
        elif commit_count >= 5:
            confidence_score += 10
        
        # File analysis quality
        if file_count >= 10:
            confidence_score += 25
        elif file_count >= 5:
            confidence_score += 15
        elif file_count >= 2:
            confidence_score += 10
        
        # Search quality
        if search_attempts >= 5 and files_checked >= 3:
            confidence_score += 25
        elif search_attempts >= 3 and files_checked >= 2:
            confidence_score += 15
        elif search_attempts >= 1:
            confidence_score += 10
        
        # Bonus for high-confidence matches
        if high_conf_matches > 0:
            confidence_score += 20
        
        # Convert to categorical confidence
        if confidence_score >= 70:
            return "HIGH"
        elif confidence_score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _assess_analysis_quality(self, commit_analysis: Dict, 
                               intra_repo_analysis: Dict, 
                               inter_repo_analysis: Dict) -> Dict:
        """Assess the quality of the analysis for reporting"""
        return {
            "commits_analyzed": commit_analysis.get("commit_count", 0),
            "files_analyzed": intra_repo_analysis.get("file_count", 0),
            "files_searched": inter_repo_analysis.get("files_checked", 0),
            "search_queries_used": inter_repo_analysis.get("search_attempts", 0),
            "high_confidence_matches": inter_repo_analysis.get("high_confidence_matches", 0),
            "total_matches": len(inter_repo_analysis.get("matches", [])),
            "similar_file_pairs": len(intra_repo_analysis.get("similar_files", []))
        }

# ============================================================================
# MAIN PLAGIARISM CHECKER
# ============================================================================

class PlagiarismChecker:
    """Main plagiarism checker orchestrating all services"""
    
    def __init__(self, github_token: str):
        self.github_service = GitHubService(github_token)
        self.commit_analyzer = CommitAnalyzer(self.github_service)
        self.similarity_service = SimilarityService(self.github_service)
        self.scoring_service = ScoringService()
    
    def check_repository(self, repo_url: str) -> Dict:
        """Main method to check a repository for plagiarism with enhanced debugging"""
        try:
            # Parse repository URL
            owner, repo = parse_github_url(repo_url)
            print(f"Analyzing repository: {owner}/{repo}")
            
            # Get basic repository info
            print("Getting repository information...")
            repo_info = self.github_service.get_repository_info(owner, repo)
            
            if not repo_info:
                raise Exception("Repository not found or inaccessible")
            
            print(f"Repository info: {repo_info.get('name', 'N/A')}, Language: {repo_info.get('language', 'N/A')}, Size: {repo_info.get('size', 0)} KB")
            
            # Run all analyses with error handling
            print("\n=== Running commit analysis ===")
            try:
                commit_analysis = self.commit_analyzer.analyze_commits(owner, repo)
                print(f"Commit analysis completed: {commit_analysis.get('commit_count', 0)} commits, score: {commit_analysis.get('score', 0):.2f}%")
            except Exception as e:
                print(f"Commit analysis failed: {e}")
                commit_analysis = {"score": 0, "indicators": ["Commit analysis failed"], "commit_count": 0}
            
            print("\n=== Running intra-repository similarity analysis ===")
            try:
                intra_repo_analysis = self.similarity_service.analyze_intra_repo_similarity(owner, repo)
                print(f"Intra-repo analysis completed: {intra_repo_analysis.get('file_count', 0)} files, score: {intra_repo_analysis.get('score', 0):.2f}%")
            except Exception as e:
                print(f"Intra-repo analysis failed: {e}")
                import traceback
                traceback.print_exc()
                intra_repo_analysis = {"score": 0, "similar_files": [], "file_count": 0}
            
            print("\n=== Running inter-repository similarity analysis ===")
            try:
                inter_repo_analysis = self.similarity_service.analyze_inter_repo_similarity(owner, repo)
                print(f"Inter-repo analysis completed: {inter_repo_analysis.get('files_checked', 0)} files checked, score: {inter_repo_analysis.get('score', 0):.2f}%")
            except Exception as e:
                print(f"Inter-repo analysis failed: {e}")
                import traceback
                traceback.print_exc()
                inter_repo_analysis = {"score": 0, "matches": [], "files_checked": 0, "search_attempts": 0}
            
            # Calculate final score
            print("\n=== Calculating final plagiarism score ===")
            final_analysis = self.scoring_service.calculate_plagiarism_score(
                commit_analysis, intra_repo_analysis, inter_repo_analysis
            )
            
            print(f"Final analysis completed: Risk Level: {final_analysis.get('risk_level', 'UNKNOWN')}, Score: {final_analysis.get('final_score', 0):.2f}%")
            
            return {
                "repository": {
                    "url": repo_url,
                    "owner": owner,
                    "name": repo,
                    "created_at": repo_info.get("created_at"),
                    "updated_at": repo_info.get("updated_at"),
                    "language": repo_info.get("language"),
                    "size": repo_info.get("size")
                },
                "analysis": {
                    "commit_patterns": commit_analysis,
                    "intra_repository_similarity": intra_repo_analysis,
                    "inter_repository_similarity": inter_repo_analysis,
                    "final_assessment": final_analysis
                },
                "timestamp": datetime.utcnow().isoformat(),
                "version": "1.1"  # Updated version
            }
            
        except Exception as e:
            print(f"Analysis failed: {e}")
            import traceback
            traceback.print_exc()
            raise Exception(f"Analysis failed: {str(e)}")

# ============================================================================
# FLASK ROUTES
# ============================================================================

# Initialize plagiarism checker
checker = PlagiarismChecker(Config.GITHUB_TOKEN)

@app.route('/githubrepocheck', methods=['POST'])
def githubrepocheck():
    """Main plagiarism check endpoint"""
    try:
        # Validate request
        if not request.is_json:
            raise BadRequest("Content-Type must be application/json")
        
        data = request.get_json()
        repo_url = data.get('repository_url')
        
        if not repo_url:
            raise BadRequest("repository_url is required")
        
        # Validate GitHub URL
        if 'github.com' not in repo_url:
            raise BadRequest("Only GitHub repositories are supported")
        
        # Run plagiarism check
        result = checker.check_repository(repo_url)
        
        return jsonify({
            "success": True,
            "data": result
        })
        
    except ValueError as e:
        return jsonify({
            "success": False,
            "error": "Invalid repository URL",
            "message": str(e)
        }), 400
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": "Analysis failed",
            "message": str(e)
        }), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Endpoint not found",
        "message": "Only endpoint is POST /githubrepocheck"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "success": False,
        "error": "Internal server error",
        "message": "An unexpected error occurred"
    }), 500

if __name__ == '__main__':
    # Check for required environment variables
    if not Config.GITHUB_TOKEN:
        print("Warning: GITHUB_TOKEN not set. API rate limits will be severely restricted.")
        print("Set GITHUB_TOKEN environment variable for better performance.")
    
    print("Starting Repository Plagiarism Checker...")
    print("API endpoint: POST http://localhost:5000/githubrepocheck")
    
    app.run(debug=True, host='0.0.0.0', port=5000)