"""
Company-specific configuration for completely independent database operations.
Each company has its own isolated configuration with no shared state.
"""

from database_managers import get_database_manager

COMPANIES = {
    'a&p': {
        'name': 'A&P',
        'color': 'blue',
        'description': 'A&P Company PORs',
        'batch_start': 5000
    },
    'fdec': {
        'name': 'FDEC',
        'color': 'green',
        'description': 'FDEC Company PORs',
        'batch_start': 6000
    }
}

class CompanyConfig:
    """Base company configuration class."""
    
    def __init__(self, company_name):
        self.company_name = company_name
        self.db_manager = get_database_manager(company_name)
        self.display_name = self._get_display_name()
        self.color = self._get_color()
        self.batch_start = self._get_batch_start()

    def get_models(self):
        """Get database models for this company."""
        return {
            'POR': self.db_manager.POR,
            'PORFile': self.db_manager.PORFile,
            'LineItem': self.db_manager.LineItem,
            'BatchCounter': self.db_manager.BatchCounter
        }
    
    def _get_display_name(self):
        """Get display name for this company."""
        names = {'a&p': 'A&P Database', 'fdec': 'FDEC Database'}
        return names.get(self.company_name, self.company_name.upper())

    @property
    def name(self):
        return self.display_name
    
    def _get_color(self):
        """Get theme color for this company."""
        return COMPANIES.get(self.company_name, {}).get('color', 'gray')
    
    def _get_batch_start(self):
        """Get batch counter start value for this company."""
        return COMPANIES.get(self.company_name, {}).get('batch_start', 5000)


class APConfig(CompanyConfig):
    """A&P Company Configuration - Completely Independent."""
    
    def __init__(self):
        super().__init__('a&p')
        self.database_file = 'a&p_por.db'
        
        # A&P specific settings
        self.fdec_warning_enabled = True  # A&P checks for FDEC warnings
        self.default_content_type = 'supply'
        self.upload_folder = 'static/uploads/ap'
    
    def check_fdec_warning(self, job_number):
        """Check if job number should trigger FDEC warning for A&P."""
        if not job_number or not self.fdec_warning_enabled:
            return None
        
        job_str = str(job_number).upper()
        if job_str.startswith('FDEC') or 'FDEC' in job_str:
            return f"⚠️ FDEC job number detected in A&P database: {job_number}"
        return None


class FDECConfig(CompanyConfig):
    """FDEC Company Configuration - Completely Independent."""
    
    def __init__(self):
        super().__init__('fdec')
        self.database_file = 'fdec_por.db'
        
        # FDEC specific settings
        self.fdec_warning_enabled = False  # FDEC doesn't need FDEC warnings
        self.default_content_type = 'work_iwo'
        self.upload_folder = 'static/uploads/fdec'
    
    def check_fdec_warning(self, job_number):
        """FDEC doesn't need FDEC warnings."""
        return None


# Create independent company configurations
ap_config = APConfig()
fdec_config = FDECConfig()

def get_company_config(company_name):
    """Get the appropriate company configuration."""
    if company_name == 'a&p':
        return ap_config
    elif company_name == 'fdec':
        return fdec_config
    else:
        raise ValueError(f"Unknown company: {company_name}")


# Convenience functions for direct access
def get_ap_config():
    """Get A&P configuration."""
    return ap_config


def get_fdec_config():
    """Get FDEC configuration."""
    return fdec_config
