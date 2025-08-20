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
    CACHE_TTL = 3600  # 1 hour
    MAX_FILES_TO_ANALYZE = 50
    MAX_COMMITS_TO_ANALYZE = 100
    RATE_LIMIT_DELAY = 1.0  # seconds between API calls
    
    # Scoring weights
    COMMIT_WEIGHT = 0.3
    INTRA_REPO_WEIGHT = 0.4
    INTER_REPO_WEIGHT = 0.3

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
    """Simple rate limiter for API calls"""
    global _last_api_call
    now = time.time()
    if now - _last_api_call < Config.RATE_LIMIT_DELAY:
        time.sleep(Config.RATE_LIMIT_DELAY - (now - _last_api_call))
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
        """Make rate-limited API request"""
        rate_limit()
        cache_key = f"github_{endpoint}_{hash(str(params))}"
        
        # Check cache first
        cached = cache_get(cache_key)
        if cached:
            return cached
        
        url = f"{self.base_url}/{endpoint}"
        try:
            response = requests.get(url, headers=self.headers, params=params or {}, timeout=30)
            
            if response.status_code == 403:
                print(f"Rate limit exceeded or forbidden: {response.text}")
                raise Exception("GitHub API rate limit exceeded or access forbidden")
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
        """Get file content from repository"""
        try:
            data = self._make_request(f"repos/{owner}/{repo}/contents/{path}", {"ref": ref})
            if data.get("encoding") == "base64":
                content = base64.b64decode(data["content"]).decode('utf-8', errors='ignore')
                return content
        except Exception as e:
            print(f"Failed to get file content for {path}: {e}")
            # Try with 'master' branch if 'main' fails
            if ref == "main":
                try:
                    data = self._make_request(f"repos/{owner}/{repo}/contents/{path}", {"ref": "master"})
                    if data.get("encoding") == "base64":
                        content = base64.b64decode(data["content"]).decode('utf-8', errors='ignore')
                        return content
                except Exception:
                    pass
        return None
    
    def get_repository_files(self, owner: str, repo: str, limit: int = 50) -> List[Dict]:
        """Get repository file tree"""
        try:
            # Try main branch first, then master
            for branch in ["main", "master"]:
                try:
                    tree_data = self._make_request(f"repos/{owner}/{repo}/git/trees/{branch}", {"recursive": "1"})
                    if tree_data and "tree" in tree_data:
                        break
                except Exception:
                    continue
            else:
                return []
            
            files = []
            for item in tree_data.get("tree", []):
                if item["type"] == "blob" and self._is_code_file(item["path"]):
                    files.append(item)
                    if len(files) >= limit:
                        break
            
            return files
        except Exception as e:
            print(f"Failed to get repository files: {e}")
            return []
    
    def search_code(self, query: str, language: str = None) -> List[Dict]:
        """Search for code across GitHub"""
        # Clean and validate query
        query = query.strip()
        if len(query) < 10:  # GitHub requires minimum query length
            print(f"Query too short: {query}")
            return []
        
        # Escape special characters and ensure it's searchable
        query = query.replace('"', '\\"')
        search_query = f'"{query}"'
        
        if language:
            search_query += f" language:{language}"
        
        params = {"q": search_query, "per_page": 10}
        
        try:
            print(f"Searching GitHub for: {search_query}")
            result = self._make_request("search/code", params)
            items = result.get("items", [])
            print(f"Found {len(items)} results")
            return items
        except Exception as e:
            print(f"Search failed: {e}")
            return []
    
    @staticmethod
    def _is_code_file(path: str) -> bool:
        """Check if file is a code file based on extension"""
        code_extensions = {'.py', '.js', '.java', '.cpp', '.c', '.h', '.cs', '.php', '.rb', '.go'}
        return any(path.endswith(ext) for ext in code_extensions)

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
        """Analyze similarity within the repository"""
        files = self.github.get_repository_files(owner, repo, Config.MAX_FILES_TO_ANALYZE)
        
        if len(files) < 2:
            return {"score": 0, "similar_files": [], "file_count": len(files)}
        
        # Get file contents
        file_contents = {}
        for file_info in files[:10]:  # Limit to avoid too many API calls
            content = self.github.get_file_content(owner, repo, file_info["path"])
            if content and len(content.strip()) > 50:  # Only include substantial files
                file_contents[file_info["path"]] = content
        
        if len(file_contents) < 2:
            return {"score": 0, "similar_files": [], "file_count": len(file_contents)}
        
        # Compare files for similarity
        similar_pairs = []
        file_paths = list(file_contents.keys())
        
        for i in range(len(file_paths)):
            for j in range(i + 1, len(file_paths)):
                path1, path2 = file_paths[i], file_paths[j]
                similarity = self._calculate_similarity(
                    file_contents[path1], 
                    file_contents[path2]
                )
                
                if similarity > 0.6:  # 60% similarity threshold
                    similar_pairs.append({
                        "file1": path1,
                        "file2": path2,
                        "similarity": round(similarity, 3)
                    })
        
        # Calculate score based on similar pairs
        max_possible_pairs = len(file_paths) * (len(file_paths) - 1) // 2
        similarity_ratio = len(similar_pairs) / max_possible_pairs if max_possible_pairs > 0 else 0
        
        return {
            "score": min(similarity_ratio * 200, 100),  # Amplify the score
            "similar_files": similar_pairs,
            "file_count": len(file_contents)
        }
    
    def analyze_inter_repo_similarity(self, owner: str, repo: str) -> Dict:
        """Analyze similarity with other repositories - FIXED VERSION"""
        files = self.github.get_repository_files(owner, repo, 10)
        
        if not files:
            return {"score": 0, "matches": [], "files_checked": 0}
        
        matches = []
        files_checked = 0
        total_search_attempts = 0
        
        print(f"Analyzing {len(files)} files for inter-repo similarity...")
        
        for file_info in files[:5]:  # Limit to first 5 files
            content = self.github.get_file_content(owner, repo, file_info["path"])
            if not content or len(content.strip()) < 100:  # Skip small files
                continue
            
            files_checked += 1
            print(f"Checking file: {file_info['path']}")
            
            # Extract multiple code snippets for better coverage
            snippets = self._extract_multiple_snippets(content)
            
            for snippet in snippets:
                if not snippet or len(snippet.strip()) < 20:
                    continue
                
                total_search_attempts += 1
                
                # Determine language from file extension
                language = self._get_language_from_path(file_info["path"])
                
                # Search for similar code
                search_results = self.github.search_code(snippet, language)
                
                for result in search_results[:3]:  # Limit results
                    result_repo = f"{result['repository']['owner']['login']}/{result['repository']['name']}"
                    if result_repo != f"{owner}/{repo}":
                        matches.append({
                            "file": file_info["path"],
                            "match_repo": result_repo,
                            "match_file": result["path"],
                            "snippet": snippet[:100] + "..." if len(snippet) > 100 else snippet,
                            "match_url": result.get("html_url", "")
                        })
                        print(f"Found match in {result_repo}")
                
                # Break if we found matches to avoid too many API calls
                if len(matches) >= 3:
                    break
            
            if len(matches) >= 3:
                break
        
        # Calculate score based on matches found
        if files_checked > 0:
            match_ratio = len(matches) / files_checked
            # Give higher weight to actual matches
            score = min(match_ratio * 150, 100)  # Amplify score if matches found
        else:
            score = 0
        
        print(f"Inter-repo analysis complete: {len(matches)} matches found from {files_checked} files")
        
        return {
            "score": score,
            "matches": matches,
            "files_checked": files_checked,
            "search_attempts": total_search_attempts
        }
    
    def _extract_multiple_snippets(self, content: str) -> List[str]:
        """Extract multiple code snippets for searching"""
        snippets = []
        
        # Normalize and clean content
        normalized = self.normalizer.normalize_code(content)
        lines = [line.strip() for line in normalized.split('\n') if line.strip()]
        
        if len(lines) < 3:
            return []
        
        # Extract function/class definitions
        function_lines = [line for line in lines if re.match(r'^\s*(def|class|function|public|private)\s+', line)]
        for line in function_lines:
            if len(line) > 15:
                snippets.append(line)
        
        # Extract distinctive code blocks (4-5 consecutive lines)
        for i in range(len(lines) - 3):
            block = '\n'.join(lines[i:i+4])
            if len(block) > 50 and not self._is_common_block(block):
                snippets.append(block)
        
        # Extract longer distinctive lines
        for line in lines:
            if len(line) > 25 and not self._is_common_line(line):
                snippets.append(line)
        
        # Remove duplicates and return top snippets
        unique_snippets = list(set(snippets))
        return unique_snippets[:5]  # Return top 5 snippets
    
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
        """Calculate final plagiarism score"""
        
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
        
        # Boost score if we have actual evidence
        if inter_repo_analysis.get("matches"):
            final_score = max(final_score, 40)  # Minimum 40 if matches found
        
        if intra_repo_analysis.get("similar_files"):
            final_score = max(final_score, 30)  # Minimum 30 if internal similarity found
        
        # Determine risk level
        if final_score >= 70:
            risk_level = "HIGH"
        elif final_score >= 40:
            risk_level = "MEDIUM"
        elif final_score >= 15:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        # Collect all indicators
        all_indicators = []
        all_indicators.extend(commit_analysis.get("indicators", []))
        
        if intra_repo_analysis.get("similar_files"):
            all_indicators.append(f"Found {len(intra_repo_analysis['similar_files'])} similar file pairs within repository")
        
        if inter_repo_analysis.get("matches"):
            all_indicators.append(f"Found {len(inter_repo_analysis['matches'])} potential matches in other repositories")
        
        return {
            "final_score": round(final_score, 2),
            "risk_level": risk_level,
            "component_scores": {
                "commit_patterns": round(commit_score, 2),
                "intra_repository_similarity": round(intra_score, 2),
                "inter_repository_similarity": round(inter_score, 2)
            },
            "indicators": all_indicators,
            "confidence": self._calculate_confidence(commit_analysis, intra_repo_analysis, inter_repo_analysis)
        }
    
    def _calculate_confidence(self, commit_analysis: Dict, 
                            intra_repo_analysis: Dict, 
                            inter_repo_analysis: Dict) -> str:
        """Calculate confidence level based on available data"""
        
        commit_count = commit_analysis.get("commit_count", 0)
        file_count = intra_repo_analysis.get("file_count", 0)
        files_checked = inter_repo_analysis.get("files_checked", 0)
        
        # Base confidence on amount of data analyzed
        if commit_count >= 10 and file_count >= 5 and files_checked >= 2:
            return "HIGH"
        elif commit_count >= 5 and file_count >= 2 and files_checked >= 1:
            return "MEDIUM"
        else:
            return "LOW"

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
        """Main method to check a repository for plagiarism"""
        try:
            # Parse repository URL
            owner, repo = parse_github_url(repo_url)
            print(f"Analyzing repository: {owner}/{repo}")
            
            # Get basic repository info
            repo_info = self.github_service.get_repository_info(owner, repo)
            
            # Run all analyses
            print("Running commit analysis...")
            commit_analysis = self.commit_analyzer.analyze_commits(owner, repo)
            
            print("Running intra-repository similarity analysis...")
            intra_repo_analysis = self.similarity_service.analyze_intra_repo_similarity(owner, repo)
            
            print("Running inter-repository similarity analysis...")
            inter_repo_analysis = self.similarity_service.analyze_inter_repo_similarity(owner, repo)
            
            # Calculate final score
            print("Calculating final plagiarism score...")
            final_analysis = self.scoring_service.calculate_plagiarism_score(
                commit_analysis, intra_repo_analysis, inter_repo_analysis
            )
            
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
                "version": "1.0"
            }
            
        except Exception as e:
            print(f"Analysis failed: {e}")
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