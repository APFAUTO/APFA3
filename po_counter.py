"""
PO Counter Module for A&P POR Automator

This module manages the Purchase Order counter functionality,
providing functions to increment, retrieve, and set PO numbers.
"""

import os
import json
from typing import Optional

# Default counter file path
DEFAULT_COUNTER_PATH = "po_counter.txt"

def po_counter_path() -> str:
    """
    Get the path to the PO counter file.
    
    Returns:
        str: Path to the counter file
    """
    return DEFAULT_COUNTER_PATH

def current_po() -> int:
    """
    Get the current PO number.
    
    Returns:
        int: Current PO number, defaults to 1000 if file doesn't exist
    """
    counter_file = po_counter_path()
    
    if not os.path.exists(counter_file):
        # Create default counter file
        set_po_value(1000)
        return 1000
    
    try:
        with open(counter_file, 'r') as f:
            content = f.read().strip()
            return int(content) if content else 1000
    except (ValueError, IOError):
        # If file is corrupted or can't be read, reset to default
        set_po_value(1000)
        return 1000

def increment_po() -> int:
    """
    Increment the PO counter and return the new value.
    
    Returns:
        int: New PO number after increment
    """
    current_value = current_po()
    new_value = current_value + 1
    set_po_value(new_value)
    return new_value

def set_po_value(value: int) -> None:
    """
    Set the PO counter to a specific value.
    
    Args:
        value (int): New PO number value
    """
    counter_file = po_counter_path()
    
    try:
        with open(counter_file, 'w') as f:
            f.write(str(value))
    except IOError as e:
        print(f"Warning: Could not write to counter file: {e}")

def reset_po_counter(value: int = 1000) -> None:
    """
    Reset the PO counter to a specific value (default: 1000).
    
    Args:
        value (int): Value to reset counter to
    """
    set_po_value(value)

def get_next_po() -> int:
    """
    Get the next PO number without incrementing the counter.
    
    Returns:
        int: Next PO number that would be assigned
    """
    return current_po() + 1

# Initialize counter file if it doesn't exist
if not os.path.exists(po_counter_path()):
    set_po_value(1000)
