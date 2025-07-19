#!/usr/bin/env python3
# Copyright 2023 Volodymyr Melnyk
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
PKI State Comparison Script

This script compares two PKI state dumps (JSON files) and displays:
1. A tree view of the new configuration
2. A tree view showing only the differences 
3. A tree view of the old configuration

Changes are highlighted with colors and symbols to show additions, modifications, and deletions.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class ChangeType(Enum):
    ADDED = "added"
    MODIFIED = "modified"
    REMOVED = "removed"
    UNCHANGED = "unchanged"


@dataclass
class Change:
    path: str
    change_type: ChangeType
    old_value: Any = None
    new_value: Any = None
    
    def __str__(self) -> str:
        if self.change_type == ChangeType.ADDED:
            return f"+ {self.path}: {self.new_value}"
        elif self.change_type == ChangeType.REMOVED:
            return f"- {self.path}: {self.old_value}"
        elif self.change_type == ChangeType.MODIFIED:
            return f"~ {self.path}: {self.old_value} → {self.new_value}"
        else:
            return f"  {self.path}: {self.new_value}"


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    @classmethod
    def disable_colors(cls):
        """Disable colors for non-terminal output"""
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = cls.MAGENTA = ""
        cls.CYAN = cls.WHITE = cls.GRAY = cls.BOLD = cls.UNDERLINE = cls.RESET = ""


class PKIStateComparator:
    """Main class for comparing PKI states and generating visual diffs"""
    
    def __init__(self, use_colors: bool = True):
        self.use_colors = use_colors
        if not use_colors:
            Colors.disable_colors()
        self.changes: List[Change] = []
        
    def load_state(self, file_path: str) -> Dict[str, Any]:
        """Load PKI state from JSON file"""
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
            sys.exit(1)
    
    def compare_states(self, old_state: Dict[str, Any], new_state: Dict[str, Any]) -> List[Change]:
        """Compare two PKI states and return list of changes"""
        self.changes = []
        self._compare_recursive(old_state, new_state, "")
        return self.changes
    
    def _compare_recursive(self, old_obj: Any, new_obj: Any, path: str):
        """Recursively compare objects and track changes"""
        
        # Handle None cases
        if old_obj is None and new_obj is None:
            return
        elif old_obj is None and new_obj is not None:
            self._add_change(path, ChangeType.ADDED, None, new_obj)
            return
        elif old_obj is not None and new_obj is None:
            self._add_change(path, ChangeType.REMOVED, old_obj, None)
            return
        
        # Handle different types
        if type(old_obj) != type(new_obj):
            self._add_change(path, ChangeType.MODIFIED, old_obj, new_obj)
            return
        
        # Handle dictionaries
        if isinstance(old_obj, dict) and isinstance(new_obj, dict):
            all_keys = set(old_obj.keys()) | set(new_obj.keys())
            
            for key in sorted(all_keys):
                key_path = f"{path}.{key}" if path else key
                
                if key in old_obj and key in new_obj:
                    self._compare_recursive(old_obj[key], new_obj[key], key_path)
                elif key in new_obj:
                    self._add_change(key_path, ChangeType.ADDED, None, new_obj[key])
                else:  # key in old_obj
                    self._add_change(key_path, ChangeType.REMOVED, old_obj[key], None)
        
        # Handle lists
        elif isinstance(old_obj, list) and isinstance(new_obj, list):
            max_len = max(len(old_obj), len(new_obj))
            
            for i in range(max_len):
                item_path = f"{path}[{i}]"
                
                if i < len(old_obj) and i < len(new_obj):
                    self._compare_recursive(old_obj[i], new_obj[i], item_path)
                elif i < len(new_obj):
                    self._add_change(item_path, ChangeType.ADDED, None, new_obj[i])
                else:  # i < len(old_obj)
                    self._add_change(item_path, ChangeType.REMOVED, old_obj[i], None)
        
        # Handle primitive values
        else:
            if old_obj != new_obj:
                self._add_change(path, ChangeType.MODIFIED, old_obj, new_obj)
    
    def _add_change(self, path: str, change_type: ChangeType, old_value: Any, new_value: Any):
        """Add a change to the changes list"""
        self.changes.append(Change(path, change_type, old_value, new_value))
    
    def print_tree(self, state: Dict[str, Any], title: str, changes_filter: Optional[Set[ChangeType]] = None, old_state: Optional[Dict[str, Any]] = None):
        """Print a tree view of the PKI state"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{title:^60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        if not state or 'authorities' not in state:
            print(f"{Colors.GRAY}(Empty or invalid state){Colors.RESET}")
            return
        
        authorities = state['authorities']
        if not authorities:
            print(f"{Colors.GRAY}(No authorities found){Colors.RESET}")
            return
        
        # When filtering for changes, include removed CAs from old state
        all_ca_names = set(authorities.keys())
        if changes_filter and old_state and ChangeType.REMOVED in changes_filter:
            old_authorities = old_state.get('authorities', {})
            for old_ca_name in old_authorities.keys():
                ca_path = f"authorities.{old_ca_name}"
                if self._get_change_for_path(ca_path) == ChangeType.REMOVED:
                    all_ca_names.add(old_ca_name)
        
        # Print root CAs
        ca_items = []
        for ca_name in sorted(all_ca_names):
            if ca_name in authorities:
                ca_items.append((ca_name, authorities[ca_name], False))  # Not removed
            else:
                # This is a removed CA, get it from old state
                old_authorities = old_state.get('authorities', {}) if old_state else {}
                if ca_name in old_authorities:
                    ca_items.append((ca_name, old_authorities[ca_name], True))  # Removed
        
        for i, (ca_name, ca_data, is_removed) in enumerate(ca_items):
            is_last_root = (i == len(ca_items) - 1)
            self._print_ca_tree(ca_name, ca_data, "", is_last_root, changes_filter, "", old_state, is_removed)
    
    def _print_ca_tree(self, ca_name: str, ca_data: Dict[str, Any], prefix: str, is_last: bool, 
                       changes_filter: Optional[Set[ChangeType]] = None, parent_path: str = "", old_state: Optional[Dict[str, Any]] = None, is_removed: bool = False):
        """Print a CA and its subtree"""
        
        # Determine tree symbols
        current_symbol = "└── " if is_last else "├── "
        next_prefix = prefix + ("    " if is_last else "│   ")
        
        # Build the correct path for this CA
        if parent_path:
            ca_path = f"{parent_path}.authorities.{ca_name}"
        else:
            ca_path = f"authorities.{ca_name}"
        ca_change = self._get_change_for_path(ca_path)
        
        # Skip if filtering and this change type is not included AND no children have changes
        if changes_filter and ca_change not in changes_filter:
            # Check if any children have changes
            has_child_changes = self._has_child_changes(ca_path, changes_filter)
            if not has_child_changes:
                return
        
        # Print CA name with color coding
        ca_color = self._get_color_for_change(ca_change)
        ca_symbol = self._get_symbol_for_change(ca_change)
        print(f"{prefix}{current_symbol}{ca_color}{ca_symbol}CA: {Colors.BOLD}{ca_name}{Colors.RESET}")
        
        # Print CA details
        if ca_data.get('own_certificate'):
            cert = ca_data['own_certificate']
            self._print_certificate_info(cert, next_prefix, "Own Certificate", ca_path, changes_filter)
        
        if ca_data.get('own_private_key'):
            key = ca_data['own_private_key']
            self._print_private_key_info(key, next_prefix, "Private Key", ca_path, changes_filter)
        
        # Print issued certificates (including removed ones when filtering)
        issued_certs = ca_data.get('issued_certificates', {})
        
        # If this is a removed CA, show all certificates from the CA's data (which comes from old state)
        # Otherwise, collect certificates normally and add removed ones if filtering
        if is_removed:
            # For removed CAs, show all certificates from the old state
            all_cert_names = set(issued_certs.keys()) if issued_certs else set()
        else:
            # For existing CAs, start with current certificates and add removed ones if filtering
            all_cert_names = set(issued_certs.keys()) if issued_certs else set()
            if changes_filter and old_state and ChangeType.REMOVED in changes_filter:
                # Navigate to corresponding CA in old state to find removed certificates
                old_ca_data = self._get_old_ca_data(ca_path, old_state)
                if old_ca_data and 'issued_certificates' in old_ca_data:
                    for old_cert_name in old_ca_data['issued_certificates'].keys():
                        # Check if this certificate was removed
                        cert_path = f"{ca_path}.issued_certificates.{old_cert_name}"
                        if self._get_change_for_path(cert_path) == ChangeType.REMOVED:
                            all_cert_names.add(old_cert_name)
        
        # Print sub-authorities (intermediate CAs)
        sub_authorities = ca_data.get('authorities', {})
        
        if all_cert_names:
            # Use └── if no sub-authorities, ├── if there are sub-authorities
            cert_symbol = "├──" if sub_authorities else "└──"
            print(f"{next_prefix}{cert_symbol} {Colors.MAGENTA}Issued Certificates:{Colors.RESET}")
            cert_items = []
            
            # Add certificates from appropriate state
            for cert_name in sorted(all_cert_names):
                if is_removed:
                    # For removed CAs, all certificates come from the CA data (old state)
                    if cert_name in issued_certs:
                        cert_items.append((cert_name, issued_certs[cert_name], True))  # All are removed
                else:
                    # For existing CAs, check both current and old state
                    if cert_name in issued_certs:
                        cert_items.append((cert_name, issued_certs[cert_name], False))  # Not removed
                    else:
                        # This is a removed certificate, get it from old state
                        old_ca_data = self._get_old_ca_data(ca_path, old_state)
                        if old_ca_data and 'issued_certificates' in old_ca_data and cert_name in old_ca_data['issued_certificates']:
                            cert_items.append((cert_name, old_ca_data['issued_certificates'][cert_name], True))  # Removed
            
            # Create prefix for certificates under "Issued Certificates"
            certs_prefix = next_prefix + ("    " if not sub_authorities else "│   ")
            
            for j, (cert_name, cert_data, is_removed) in enumerate(cert_items):
                is_last_cert = (j == len(cert_items) - 1)
                self._print_issued_certificate(cert_name, cert_data, certs_prefix, is_last_cert, ca_path, changes_filter, is_removed)
        
        if sub_authorities:
            print(f"{next_prefix}└── {Colors.CYAN}Sub-Authorities:{Colors.RESET}")
            auth_items = list(sub_authorities.items())
            for k, (sub_ca_name, sub_ca_data) in enumerate(sorted(auth_items)):
                is_last_sub = (k == len(auth_items) - 1)
                sub_prefix = next_prefix + "    "
                self._print_ca_tree(sub_ca_name, sub_ca_data, sub_prefix, is_last_sub, changes_filter, ca_path, old_state, False)
    
    def _print_certificate_info(self, cert: Dict[str, Any], prefix: str, title: str, ca_path: str,
                               changes_filter: Optional[Set[ChangeType]] = None):
        """Print certificate information with change highlighting"""
        cert_path = f"{ca_path}.own_certificate"
        change_type = self._get_change_for_path(cert_path)
        
        if changes_filter and change_type not in changes_filter:
            return
        
        color = self._get_color_for_change(change_type)
        symbol = self._get_symbol_for_change(change_type)
        
        print(f"{prefix}├── {color}{symbol}{title}:{Colors.RESET}")
        
        if isinstance(cert, dict):
            # Print key certificate fields
            important_fields = ['subject', 'issuer', 'serial_number', 'not_valid_before', 'not_valid_after']
            for field in important_fields:
                if field in cert:
                    field_path = f"{cert_path}.{field}"
                    field_change = self._get_change_for_path(field_path)
                    if changes_filter and field_change not in changes_filter:
                        continue
                    
                    field_color = self._get_color_for_change(field_change)
                    field_symbol = self._get_symbol_for_change(field_change)
                    value = self._format_certificate_field(field, cert[field])
                    print(f"{prefix}│   ├── {field_color}{field_symbol}{field}: {value}{Colors.RESET}")
    
    def _print_private_key_info(self, key: Dict[str, Any], prefix: str, title: str, ca_path: str,
                               changes_filter: Optional[Set[ChangeType]] = None):
        """Print private key information with change highlighting"""
        key_path = f"{ca_path}.own_private_key"
        change_type = self._get_change_for_path(key_path)
        
        if changes_filter and change_type not in changes_filter:
            return
        
        color = self._get_color_for_change(change_type)
        symbol = self._get_symbol_for_change(change_type)
        
        print(f"{prefix}├── {color}{symbol}{title}:{Colors.RESET}")
        
        if isinstance(key, dict):
            # Print key fields
            important_fields = ['size', 'encrypted', 'public_exponent']
            for field in important_fields:
                if field in key:
                    field_path = f"{key_path}.{field}"
                    field_change = self._get_change_for_path(field_path)
                    if changes_filter and field_change not in changes_filter:
                        continue
                    
                    field_color = self._get_color_for_change(field_change)
                    field_symbol = self._get_symbol_for_change(field_change)
                    print(f"{prefix}│   ├── {field_color}{field_symbol}{field}: {key[field]}{Colors.RESET}")
    
    def _print_issued_certificate(self, cert_name: str, cert_data: Dict[str, Any], prefix: str, 
                                 is_last: bool, ca_path: str, changes_filter: Optional[Set[ChangeType]] = None, is_removed: bool = False):
        """Print an issued certificate with change highlighting"""
        cert_symbol = "└── " if is_last else "├── "
        cert_path = f"{ca_path}.issued_certificates.{cert_name}"
        change_type = self._get_change_for_path(cert_path)
        
        if changes_filter and change_type not in changes_filter:
            return
        
        color = self._get_color_for_change(change_type)
        symbol = self._get_symbol_for_change(change_type)
        
        cert_type = cert_data.get('type', 'unknown')
        print(f"{prefix}{cert_symbol}{color}{symbol}{cert_name} ({cert_type}){Colors.RESET}")
        
        # Print certificate details if available
        cert_info = cert_data.get('certificate')
        if cert_info and isinstance(cert_info, dict):
            next_prefix = prefix + ("    " if is_last else "│   ")
            subject = cert_info.get('subject', 'Unknown')
            validity = f"{cert_info.get('not_valid_before', 'Unknown')} - {cert_info.get('not_valid_after', 'Unknown')}"
            print(f"{next_prefix}├── Subject: {self._truncate_subject(subject)}")
            print(f"{next_prefix}└── Valid: {validity}")
    
    def _get_change_for_path(self, path: str) -> ChangeType:
        """Get the change type for a specific path"""
        # Look for exact match first
        for change in self.changes:
            if change.path == path:
                return change.change_type
        
        # Look for any child changes (this path has subchanges)
        has_child_changes = False
        for change in self.changes:
            if change.path.startswith(path + "."):
                has_child_changes = True
                if change.change_type in [ChangeType.ADDED, ChangeType.REMOVED]:
                    return change.change_type
                elif change.change_type == ChangeType.MODIFIED:
                    return ChangeType.MODIFIED
        
        # If we have child changes but no direct modifications, show as modified
        if has_child_changes:
            return ChangeType.MODIFIED
            
        return ChangeType.UNCHANGED
    
    def _has_child_changes(self, path: str, changes_filter: Set[ChangeType]) -> bool:
        """Check if any child paths have changes that match the filter"""
        for change in self.changes:
            if change.path.startswith(path + ".") and change.change_type in changes_filter:
                return True
        return False
    
    def _get_color_for_change(self, change_type: ChangeType) -> str:
        """Get color for change type"""
        if change_type == ChangeType.ADDED:
            return Colors.GREEN
        elif change_type == ChangeType.REMOVED:
            return Colors.RED
        elif change_type == ChangeType.MODIFIED:
            return Colors.YELLOW
        else:
            return Colors.RESET
    
    def _get_symbol_for_change(self, change_type: ChangeType) -> str:
        """Get symbol for change type"""
        if change_type == ChangeType.ADDED:
            return "+ "
        elif change_type == ChangeType.REMOVED:
            return "- "
        elif change_type == ChangeType.MODIFIED:
            return "~ "
        else:
            return ""
    
    def _format_certificate_field(self, field: str, value: Any) -> str:
        """Format certificate field values for display"""
        if field in ['subject', 'issuer']:
            return self._truncate_subject(str(value))
        elif field in ['not_valid_before', 'not_valid_after']:
            return str(value)[:19]  # Truncate timestamp
        else:
            return str(value)
    
    def _truncate_subject(self, subject: str) -> str:
        """Truncate long subject strings for better display"""
        if len(subject) > 80:
            return subject[:77] + "..."
        return subject
    
    def _get_old_ca_data(self, ca_path: str, old_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Navigate to corresponding CA in old state using path"""
        try:
            # Split path like "authorities.root.authorities.server" into parts
            parts = ca_path.split('.')
            current = old_state
            
            for part in parts:
                if part in current:
                    current = current[part]
                else:
                    return None
                    
            return current
        except (KeyError, TypeError):
            return None
    
    def print_summary(self, changes: List[Change]):
        """Print a summary of changes"""
        added = sum(1 for c in changes if c.change_type == ChangeType.ADDED)
        modified = sum(1 for c in changes if c.change_type == ChangeType.MODIFIED)
        removed = sum(1 for c in changes if c.change_type == ChangeType.REMOVED)
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'SUMMARY':^60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
        
        print(f"{Colors.GREEN}Added:{Colors.RESET} {added} items")
        print(f"{Colors.YELLOW}Modified:{Colors.RESET} {modified} items")
        print(f"{Colors.RED}Removed:{Colors.RESET} {removed} items")
        print(f"{Colors.BOLD}Total changes:{Colors.RESET} {len(changes)} items")
        
        if not changes:
            print(f"\n{Colors.GREEN}{Colors.BOLD}✓ No differences found - states are identical{Colors.RESET}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Compare two PKI state dumps and show differences")
    parser.add_argument("old_state", help="Path to the old PKI state JSON file")
    parser.add_argument("new_state", help="Path to the new PKI state JSON file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--changes-only", action="store_true", 
                       help="Show only the differences tree (skip full trees)")
    
    args = parser.parse_args()
    
    # Create comparator
    comparator = PKIStateComparator(use_colors=not args.no_color)
    
    # Load states
    old_state = comparator.load_state(args.old_state)
    new_state = comparator.load_state(args.new_state)
    
    # Compare states
    changes = comparator.compare_states(old_state, new_state)
    
    if not args.changes_only:
        # Print new configuration tree
        comparator.print_tree(new_state, "NEW CONFIGURATION")
    
    # Print differences tree
    change_types = {ChangeType.ADDED, ChangeType.MODIFIED, ChangeType.REMOVED}
    comparator.print_tree(new_state, "DIFFERENCES (Changes Only)", change_types, old_state)
    
    if not args.changes_only:
        # Print old configuration tree
        comparator.print_tree(old_state, "OLD CONFIGURATION")
    
    # Print summary
    comparator.print_summary(changes)


if __name__ == "__main__":
    main()