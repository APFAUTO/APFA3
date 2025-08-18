"""
Database utility functions.
"""

from database_managers import ap_db, fdec_db

def get_database_manager(company_name):
    """Get the appropriate database manager for a company."""
    if company_name == 'a&p':
        return ap_db
    elif company_name == 'fdec':
        return fdec_db
    else:
        raise ValueError(f"Unknown company: {company_name}")
