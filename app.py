"""
POR Upload Application
A Flask-based system for processing Purchase Order Requests (POR) from Excel files.
"""

import os
import logging
import json
from datetime import datetime, timezone
from typing import Optional, Tuple, List

from models import BatchCounter
from models import Base, engine
from po_counter import increment_po

# Initialize database tables
try:
    Base.metadata.create_all(engine)
    print("✅ Database tables initialized successfully")
except Exception as e:
    print(f"❌ Error initializing database: {e}")
    # Continue anyway - tables might already exist

from flask import Flask, request, render_template, flash, redirect, url_for, send_file, session, jsonify
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

from models import POR, PORFile, LineItem, get_session
from utils import read_ws, find_vertical, get_order_total_by_map, extract_line_items_by_map, to_float, stringify
from config import COMPANIES, DATABASES, CURRENT_DATABASE
import re

# NLP classifier removed - using rule-based pattern matching only
NLP_CLASSIFIER_AVAILABLE = False
nlp_classifier = None

# Configuration
UPLOAD_FOLDER = "static/uploads"

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'msg', 'eml'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB
RECORDS_PER_PAGE = 10

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask app setup
app = Flask(__name__)
app.config.update(
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=MAX_FILE_SIZE,
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
)

# Database session management
def create_database_models(database_name):
    """Create database-aware models for the specified database."""
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy import Column, Integer, String, Float, Text, DateTime, Index, ForeignKey
    from sqlalchemy.orm import relationship
    from datetime import datetime, timezone
    
    LocalBase = declarative_base()
    
    class LocalPOR(LocalBase):
        __tablename__ = "por"
        id = Column(Integer, primary_key=True, autoincrement=True)
        po_number = Column(Integer, unique=True, nullable=False, index=True)
        requestor_name = Column(String(255), nullable=False, index=True)
        date_order_raised = Column(String(50), nullable=False)
        date_required_by = Column(String(50))
        ship_project_name = Column(String(255), index=True)
        supplier = Column(String(255), index=True)
        filename = Column(String(255), nullable=False)
        company = Column(String(10), nullable=True, default='a&p')
        job_contract_no = Column(String(100), index=True)
        op_no = Column(String(50), index=True)
        description = Column(Text)
        quantity = Column(Integer)
        price_each = Column(Float)
        line_total = Column(Float)
        order_total = Column(Float)
        specification_standards = Column(Text)
        supplier_contact_name = Column(String(255))
        supplier_contact_email = Column(String(255))
        quote_ref = Column(String(255))
        quote_date = Column(String(50))
        show_price = Column(String(10))
        data_summary = Column(Text)
        created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
        current_stage = Column(String(20), default='received', nullable=False)
        status_color = Column(String(20), default='normal', nullable=False)
        order_type = Column(String(20), default='new', nullable=False)
        content_type = Column(String(20), default='supply', nullable=False)
        received_comments = Column(Text)
        sent_comments = Column(Text)
        filed_comments = Column(Text)
        amazon_comment = Column(Text)
        work_date_comment = Column(Text)
        fdec_warning = Column(Text)
        stage_updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
        change_history = Column(Text)
        current_change_index = Column(Integer, default=-1)
        
        # Relationship to attached files
        attached_files = relationship("LocalPORFile", back_populates="por", cascade="all, delete-orphan")
        
        # Composite index for common searches
        __table_args__ = (
            Index('idx_po_requestor', 'po_number', 'requestor_name'),
            Index('idx_job_op', 'job_contract_no', 'op_no'),
        )
    
    class LocalLineItem(LocalBase):
        __tablename__ = "line_items"
        id = Column(Integer, primary_key=True, autoincrement=True)
        por_id = Column(Integer, ForeignKey('por.id'), nullable=False, index=True)
        job_contract_no = Column(String(100), index=True)
        op_no = Column(String(50), index=True)
        description = Column(Text)
        specifications = Column(Text)
        quantity = Column(Integer)
        price_each = Column(Float)
        line_total = Column(Float)
    
    class LocalPORFile(LocalBase):
        __tablename__ = "por_files"
        id = Column(Integer, primary_key=True, autoincrement=True)
        por_id = Column(Integer, ForeignKey('por.id'), nullable=False, index=True)
        original_filename = Column(String(255), nullable=False)
        stored_filename = Column(String(255), nullable=False)
        file_type = Column(String(50), nullable=False)
        file_size = Column(Integer)
        mime_type = Column(String(100))
        uploaded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
        description = Column(String(500))
        por = relationship("LocalPOR", back_populates="attached_files")
    
    class LocalBatchCounter(LocalBase):
        __tablename__ = "batch_counter"
        id = Column(Integer, primary_key=True)
        value = Column(Integer, nullable=False)
    
    return LocalBase, LocalPOR, LocalLineItem, LocalPORFile, LocalBatchCounter

def get_current_database():
    """Get the current active database from session or default."""
    current_db = session.get('current_database', CURRENT_DATABASE)
    logger.info(f"[DEBUG] get_current_database() - Session value: {session.get('current_database')}, Default: {CURRENT_DATABASE}, Returning: {current_db}")
    return current_db

def get_database_engine(database_name=None):
    """Get database engine for specified database."""
    if database_name is None:
        database_name = get_current_database()
    
    db_config = DATABASES.get(database_name, DATABASES['a&p'])
    db_path = db_config['path']
    
    # Get absolute path
    import os
    abs_path = os.path.abspath(db_path)
    
    logger.info(f"[DEBUG] get_database_engine() - Database: {database_name}, Path: {db_path}, Abs Path: {abs_path}")
    
    # Create SQLite engine for the specified database
    engine = create_engine(f'sqlite:///{abs_path}')
    return engine

def get_database_session(database_name=None):
    """Get database session for specified database."""
    if database_name is None:
        database_name = get_current_database()
    
    logger.info(f"[DEBUG] get_database_session() - Creating session for database: {database_name}")
    
    engine = get_database_engine(database_name)
    Session = sessionmaker(bind=engine)
    return Session()

def get_or_create_batch_counter(database_name=None):
    """Get or create batch counter for specified database."""
    db_session = get_database_session(database_name)
    try:
        # Ensure the BatchCounter table exists in this database
        engine = get_database_engine(database_name)
        
        # Get database-aware models for this database
        LocalBase, LocalPOR, LocalLineItem, LocalPORFile, LocalBatchCounter = create_database_models(database_name)
        
        # Create the table in this database
        LocalBase.metadata.create_all(engine)
        
        # Query using the local model
        counter = db_session.query(LocalBatchCounter).first()
        if not counter:
            # Create new counter with starting value based on company
            current_db = database_name or get_current_database()
            start_value = 1000  # Default starting value
            if current_db == 'fdec':
                start_value = 1000  # FDEC starting value
            elif current_db == 'a&p':
                start_value = 1000  # A&P starting value
            
            counter = LocalBatchCounter(value=start_value)
            db_session.add(counter)
            db_session.commit()
        return counter
    finally:
        db_session.close()

# Enable development mode for auto-reloading

# Add cache-busting headers to all responses
@app.after_request
def add_cache_headers(response):
    """Add cache-busting headers to prevent browser caching."""
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    allowed_extensions = {'xlsx', 'xls', 'msg', 'eml', 'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


def allowed_excel_file(filename: str) -> bool:
    """Check if file extension is allowed for main POR uploader (Excel only)."""
    allowed_extensions = {'xlsx', 'xls'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


def get_file_type_icon(file_type: str) -> str:
    """Get the appropriate icon for a file type."""
    icon_map = {
        'quote': '💰',
        'original': '📄',
        'correspondence': '📝',
        'updates': '🔄',
        'por': '📋',
        'other': '📎'
    }
    return icon_map.get(file_type, '📎')


def capitalize_text(value):
    """Capitalize text values, handling None and non-string values."""
    if value is None:
        return None
    if isinstance(value, str):
        return value.upper()
    return value

def clean_query_string(query_string):
    """Custom filter to clean query string by removing from_search parameter."""
    if not query_string:
        return ''
    
    # Parse the query string
    from urllib.parse import parse_qs, urlencode
    params = parse_qs(query_string)
    
    # Remove the from_search parameter if it exists
    if 'from_search' in params:
        del params['from_search']
    
    # Rebuild the query string
    return urlencode(params, doseq=True)


def detect_company_from_project(job_contract_no: str) -> str:
    """Detect company based on project number."""
    if not job_contract_no:
        return 'a&p'  # Default to A&P if no project number
    
    return 'a&p'  # Default to A&P


def get_company_info(company: str) -> dict:
    """Get company configuration information."""
    return COMPANIES['a&p']


def add_change_to_history(por, field, old_value, new_value):
    """Add a change to the POR's change history."""
    try:
        # Parse existing history
        history = json.loads(por.change_history) if por.change_history else []
        
        # Create change record
        change = {
            'field': field,
            'old_value': old_value,
            'new_value': new_value,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Add to history
        history.append(change)
        
        # Limit to 100 changes
        if len(history) > 100:
            history = history[-100:]
        
        # Update POR
        por.change_history = json.dumps(history)
        por.current_change_index = len(history) - 1
        
        return True
    except Exception as e:
        logger.error(f"Error adding change to history: {str(e)}")
        return False


def undo_last_change(por):
    """Undo the last change for a POR."""
    try:
        # Parse existing history
        history = json.loads(por.change_history) if por.change_history else []
        
        if not history or por.current_change_index < 0:
            return False, "No changes to undo"
        
        # Get the last change
        change = history[por.current_change_index]
        
        # Revert the field
        setattr(por, change['field'], change['old_value'])
        
        # Move index back
        por.current_change_index -= 1
        
        return True, f"Undid change to {change['field']}"
        
    except Exception as e:
        logger.error(f"Error undoing change: {str(e)}")
        return False, str(e)


def redo_last_change(por):
    """Redo the last undone change for a POR."""
    try:
        # Parse existing history
        history = json.loads(por.change_history) if por.change_history else []
        
        if not history or por.current_change_index >= len(history) - 1:
            return False, "No changes to redo"
        
        # Get the next change
        change = history[por.current_change_index + 1]
        
        # Apply the change
        setattr(por, change['field'], change['new_value'])
        
        # Move index forward
        por.current_change_index += 1
        
        return True, f"Redid change to {change['field']}"
        
    except Exception as e:
        logger.error(f"Error redoing change: {str(e)}")
        return False, str(e)


def detect_content_type_from_line_items(line_items: list, por_description: str = "") -> str:
    """Detect content type based on line item descriptions using rule-based pattern matching."""
    
    # Combine all line item descriptions for comprehensive analysis
    all_descriptions = []
    for item in line_items:
        desc = item.get('desc', '') or ''
        if desc:
            all_descriptions.append(desc)
    
    # Also include POR description if available
    if por_description:
        all_descriptions.append(por_description)
    
    if all_descriptions:
        # Join all descriptions for comprehensive analysis
        combined_text = ' '.join(all_descriptions)
        
        # Use rule-based pattern matching for content type detection
        logger.info("📝 Using rule-based pattern matching for content type detection")
    
    # Work IWO patterns (highest priority)
    work_iwo_patterns = [
        r'work\s+iwo',
        r'provide\s+labour\s+iwo',
        r'labour\s+iwo',
        r'iwo\s+work',
        r'work\s+only',
        r'labour\s+only',
        r'provide\s+labour',
        r'labour\s+services',
        r'work\s+services',
        r'installation\s+work',
        r'fitting\s+work',
        r'repair\s+work',
        r'maintenance\s+work'
    ]
    
    # Supply and Fit patterns
    supply_fit_patterns = [
        r'supply\s+and\s+fit',
        r'supply\s*&\s*fit',
        r'fit\s+and\s+supply',
        r'install\s+and\s+supply',
        r'supply\s+install',
        r'install\s+supply',
        r'fitting\s+and\s+supply',
        r'supply\s+and\s+installation',
        r'installation\s+and\s+supply',
        r'fit\s+supply',
        r'supply\s+fit',
        r'install\s+supply',
        r'supply\s+install'
    ]
    
    def fuzzy_match(text, patterns):
        """Fuzzy matching for content type detection."""
        if not text:
            return False
        
        text_lower = text.lower()
        
        for pattern in patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True
        
        return False
    
    # Check all line items for patterns
    for item in line_items:
        description = item.get('desc', "") or ""
        
        # Check for Work IWO first (highest priority)
        if fuzzy_match(description, work_iwo_patterns):
            return 'work_iwo'
        
        # Check for Supply and Fit
        if fuzzy_match(description, supply_fit_patterns):
            return 'supply_and_fit'
    
    # Check POR description as fallback
    if por_description:
        if fuzzy_match(por_description, work_iwo_patterns):
            return 'work_iwo'
        if fuzzy_match(por_description, supply_fit_patterns):
            return 'supply_and_fit'
    
    # Default to supply if no patterns found
    return 'supply'


def process_uploaded_file(file) -> Tuple[bool, str, Optional[dict], Optional[list]]:
    """
    Process uploaded Excel file or email file and extract POR data and line items.
    Returns:
        Tuple of (success, message, data_dict, line_items)
    """
    try:
        # Validate file
        if not file or file.filename == '':
            logger.warning("No file selected or empty filename")
            return False, "No file selected", None, None
        
        # Handle case where file might be empty or corrupted
        try:
            file.seek(0)
            file_content = file.read(1)
            file.seek(0)
            if not file_content:
                logger.warning("File appears to be empty")
                return False, "File appears to be empty. Please try uploading again.", None, None
        except Exception as e:
            logger.error(f"Error checking file content: {str(e)}")
            return False, "Error reading file. Please try uploading again.", None, None
        
        # Log file information for debugging
        logger.info(f"Processing file: {file.filename}")
        logger.info(f"File content type: {getattr(file, 'content_type', 'unknown')}")
        logger.info(f"File size: {getattr(file, 'content_length', 'unknown')}")
        
        # Clean filename - remove any problematic characters
        clean_filename = file.filename.strip()
        if clean_filename != file.filename:
            logger.info(f"Cleaned filename from '{file.filename}' to '{clean_filename}'")
            file.filename = clean_filename
        
        # Handle Outlook Classic .msg files that might have different formatting
        if 'msg' in file.filename.lower() and not file.filename.lower().endswith('.msg'):
            # Try to fix common Outlook Classic filename issues
            if '_' in file.filename and not file.filename.endswith('.msg'):
                # Add .msg extension if missing
                file.filename = file.filename + '.msg'
                logger.info(f"Added .msg extension to filename: {file.filename}")
        
        # For main POR uploader, we only process Excel files
        if not allowed_excel_file(file.filename):
            logger.warning(f"File type not allowed for main uploader: {file.filename}")
            return False, "Only Excel files (.xlsx, .xls) are allowed for POR uploads", None, None
        
        # Check file extension
        file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        logger.info(f"File extension detected: {file_extension}")
        
        # If no extension in filename, try to detect from content (Excel only for main uploader)
        if not file_extension:
            try:
                file.seek(0)
                first_bytes = file.read(8)
                file.seek(0)
                logger.info(f"File header bytes: {first_bytes}")
                
                # Detect Excel file type from content
                if first_bytes.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
                    if 'xls' in file.filename.lower():
                        file_extension = 'xls'
                        logger.info("Detected .xls file from content")
                elif first_bytes.startswith(b'PK'):
                    file_extension = 'xlsx'
                    logger.info("Detected .xlsx file from content")
            except Exception as e:
                logger.error(f"Error detecting file type from content: {str(e)}")
        
        # For main uploader, only process Excel files
        logger.info("Processing as Excel file")
        return process_excel_file(file)
            
    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        return False, f"❌ Error processing file: {str(e)}", None, None


def process_excel_file(file) -> Tuple[bool, str, Optional[dict], Optional[list]]:
    """Process Excel file and extract POR data according to the parsing map."""
    try:
        # Read file content into memory first to avoid stream consumption issues
        file.seek(0)
        file_content = file.read()
        file.seek(0)
        
        # Create a BytesIO object for processing
        from io import BytesIO
        file_stream = BytesIO(file_content)
        
        # Read worksheet
        rows, ws = read_ws(file_stream)
        if not rows:
            return False, "Empty or invalid Excel file", None, None
        
        # Extract data according to the exact POR parsing map
        from utils import extract_por_data_by_map, extract_line_items_by_map, get_order_total_by_map
        
        # Extract all POR data using the parsing map
        por_data = extract_por_data_by_map(ws)
        
        # Extract line items using the parsing map
        items = extract_line_items_by_map(ws)
        
        # Get order total using the parsing map
        order_total = get_order_total_by_map(ws)
        
        # Generate PO number and filename using database-aware counter
        current_db = get_current_database()
        counter = get_or_create_batch_counter(current_db)
        po_number = counter.value
        # Increment the counter for next use
        counter.value += 1
        # Save the updated counter
        counter_session = get_database_session(current_db)
        counter_session.add(counter)
        counter_session.commit()
        counter_session.close()
        
        date_order = por_data.get('date_order_raised', datetime.now().strftime('%d/%m/%Y'))
        requestor = por_data.get('requestor_name', 'Unknown')
        
        # Preserve original file extension
        original_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'xlsx'
        safe_filename = secure_filename(f'PO_{po_number}_{date_order}_{requestor.replace(" ", "_")}.{original_extension}')
        
        # Save file locally
        try:
            file.seek(0)
            file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
            file.save(file_path)
        except Exception as e:
            logger.error(f"Error saving file: {str(e)}")
            return False, f"❌ Error saving file: {str(e)}", None, None
        
        # Capitalize text fields in line items
        for item in items:
            item['job'] = capitalize_text(item.get('job'))
            item['op'] = capitalize_text(item.get('op'))
            item['desc'] = capitalize_text(item.get('desc'))
        
        first_item = items[0] if items else {}
        
        # Check for FDEC job number warning
        current_db = get_current_database()
        fdec_warning = check_fdec_job_warning(first_item.get('job'), current_db)
        
        # Prepare data dictionary
        data = {
            'po_number': po_number,
            'requestor_name': requestor,
            'date_order_raised': date_order,
            'date_required_by': por_data.get('date_required_by', ''),
            'show_price': por_data.get('show_price', ''),
            'ship_project_name': por_data.get('ship_project_name', ''),
            'supplier': por_data.get('supplier', ''),
            'filename': safe_filename,
            'company': current_db,  # Use current database instead of hardcoded 'a&p'
            'job_contract_no': first_item.get('job'),
            'op_no': first_item.get('op'),
            'description': first_item.get('desc'),
            'quantity': first_item.get('qty'),
            'price_each': to_float(first_item.get('price')),
            'line_total': to_float(first_item.get('ltot')),
            'order_total': order_total,
            'specification_standards': por_data.get('specification_standards', ''),
            'supplier_contact_name': por_data.get('supplier_contact_name', ''),
            'supplier_contact_email': por_data.get('supplier_contact_email', ''),
            'quote_ref': por_data.get('quote_ref', ''),
            'quote_date': por_data.get('quote_date', ''),
            'data_summary': "\n".join(str(r) for r in rows[:10]),
            'created_at': datetime.now(timezone.utc),
            'fdec_warning': fdec_warning  # Include warning in data
        }
        
        logger.info(f"✅ Successfully processed PO #{po_number} with {len(items)} line items")
        logger.info(f"📊 Extracted data: Requestor={requestor}, Project={por_data.get('ship_project_name')}, Supplier={por_data.get('supplier')}")
        
        return True, f"✅ Successfully processed PO #{po_number}", data, items
        
    except Exception as e:
        logger.error(f"Error processing Excel file: {str(e)}")
        # Provide more specific error message for format issues
        if "Excel 97-2003" in str(e) or "xlrd" in str(e):
            return False, f"❌ Error processing Excel 97-2003 file: {str(e)}. Please ensure the file is not corrupted.", None, None
        elif "openpyxl" in str(e) or "xlsx" in str(e):
            return False, f"❌ Error processing Excel file: {str(e)}. Please ensure the file is not corrupted.", None, None
        else:
            return False, f"❌ Error processing Excel file: {str(e)}", None, None


def process_email_file(file) -> Tuple[bool, str, Optional[dict], Optional[list]]:
    """Process email file (.msg or .eml) and extract POR data."""
    try:
        import email
        from email import policy
        
        # Generate PO number and filename
        po_number = increment_po()
        date_order = datetime.now().strftime('%d/%m/%Y')
        
        # Save file locally
        original_filename = secure_filename(file.filename)
        safe_filename = secure_filename(f'PO_{po_number}_{date_order}_EMAIL_{original_filename}')
        
        try:
            file.seek(0)
            file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
            file.save(file_path)
        except Exception as e:
            logger.error(f"Error saving email file: {str(e)}")
            return False, f"❌ Error saving email file: {str(e)}", None, None
        
        # Parse email content
        file.seek(0)
        if file.filename.lower().endswith('.msg'):
            # For .msg files, we'll extract basic info
            # Note: Full .msg parsing requires additional libraries like extract-msg
            email_data = {
                'subject': 'Email Subject (MSG file)',
                'from': 'Unknown Sender',
                'date': date_order,
                'body': 'MSG file content - manual processing required'
            }
        else:
            # Parse .eml file
            msg = email.message_from_file(file, policy=policy.default)
            
            # Extract email headers
            subject = msg.get('subject', 'No Subject')
            from_header = msg.get('from', 'Unknown Sender')
            date_header = msg.get('date', '')
            
            # Extract email body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_content()
                        break
            else:
                body = msg.get_content()
            
            email_data = {
                'subject': subject,
                'from': from_header,
                'date': date_header,
                'body': body
            }
        
        # Extract basic POR data from email
        # This is a simplified extraction - you may need to customize based on your email format
        requestor = capitalize_text(email_data['from'].split('<')[0].strip() if '<' in email_data['from'] else email_data['from'])
        
        # Try to extract supplier from subject or body
        supplier = 'Unknown'
        if 'supplier' in email_data['subject'].lower():
            supplier = capitalize_text(email_data['subject'])
        
        # Prepare data
        data = {
            'po_number': po_number,
            'requestor_name': requestor,
            'date_order_raised': date_order,
            'ship_project_name': 'Email Upload',
            'supplier': supplier,
            'filename': safe_filename,
            'job_contract_no': '',
            'op_no': '',
            'description': email_data['subject'][:100],  # Use subject as description
            'quantity': 1,
            'price_each': 0.0,
            'line_total': 0.0,
            'order_total': 0.0,
            'specification_standards': '',
            'supplier_contact_name': '',
            'supplier_contact_email': email_data['from'],
            'quote_ref': '',
            'quote_date': '',
            'data_summary': f"Email Subject: {email_data['subject']}\nFrom: {email_data['from']}\nDate: {email_data['date']}\n\nBody Preview:\n{email_data['body'][:500]}...",
            'created_at': datetime.now(timezone.utc)
        }
        
        # Create a simple line item from email data
        items = [{
            'job': '',
            'op': '',
            'desc': email_data['subject'],
            'qty': 1,
            'price': 0.0,
            'ltot': 0.0
        }]
        
        return True, f"✅ Successfully processed Email PO #{po_number}", data, items
        
    except Exception as e:
        logger.error(f"Error processing email file: {str(e)}")
        return False, f"❌ Error processing email file: {str(e)}", None, None


def save_por_to_database(data: dict, line_items: list = None) -> Tuple[bool, str]:
    """Save POR data and its line items to database."""
    try:
        import re
        
        logger.info(f"🔍 Starting database save for PO #{data.get('po_number')} in database: {get_current_database()}")
        
        # Check for batch number conflicts between companies
        current_db = get_current_database()
        logger.info(f"🔍 Checking batch number conflicts for PO #{data.get('po_number')}")
        batch_conflict = check_batch_number_conflict(data.get('po_number'), current_db)
        if batch_conflict:
            logger.warning(f"🚫 BATCH NUMBER CONFLICT BLOCKS UPLOAD: {batch_conflict}")
            return False, batch_conflict
        
        logger.info(f"✅ No batch number conflicts found")
        
        # Get database session
        logger.info(f"🔍 Getting database session for {current_db}")
        db_session = get_database_session(current_db)
        
        # Get database-aware models for this database
        logger.info(f"🔍 Creating database-aware models for {current_db}")
        LocalBase, LocalPOR, LocalLineItem, LocalPORFile, LocalBatchCounter = create_database_models(current_db)
        
        # Create tables in this database
        logger.info(f"🔍 Creating tables in {current_db} database")
        engine = get_database_engine(current_db)
        LocalBase.metadata.create_all(engine)
        
        logger.info(f"🔍 Creating POR object with data: {data}")
        por = LocalPOR(**data)
        db_session.add(por)
        logger.info(f"🔍 Flushing to get POR ID")
        db_session.flush()  # Get POR id
        logger.info(f"✅ POR created with ID: {por.id}")
        
        # Save line items if provided
        if line_items:
            logger.info(f"🔍 Saving {len(line_items)} line items")
            for i, item in enumerate(line_items):
                line_item = LocalLineItem(
                    por_id=por.id,
                    job_contract_no=item.get('job'),
                    op_no=item.get('op'),
                    description=item.get('desc'),
                    quantity=item.get('qty'),
                    price_each=to_float(item.get('price')),
                    line_total=to_float(item.get('ltot'))
                )
                db_session.add(line_item)
                logger.info(f"✅ Line item {i+1} added: {item.get('desc', 'No description')}")
        
        # Auto-detect content type based on line items
        if line_items:
            logger.info(f"🔍 Detecting content type for PO {por.po_number} using Rule-based patterns")
            content_type = detect_content_type_from_line_items(line_items, por.description or "")
            por.content_type = content_type
            logger.info(f"✅ Auto-detected content type for PO {por.po_number}: {content_type}")
        
        # Check if supplier is Amazon and create comment line
        if por.supplier:
            supplier_lower = por.supplier.lower()
            # More precise Amazon detection - check for exact word boundaries
            amazon_patterns = [
                'amazon',
                'amazon uk',
                'amazon.com',
                'amazon prime',
                'amazon marketplace'
            ]
            
            is_amazon = any(pattern in supplier_lower for pattern in amazon_patterns)
            
            # Additional check to avoid false positives
            if is_amazon and not any(exclude in supplier_lower for exclude in ['not amazon', 'amazonia', 'amazonian']):
                amazon_comment = "ENTER ORDER NO. HERE"
                
                # Add to amazon_comment field
                por.amazon_comment = amazon_comment
                
                logger.info(f"Added Amazon comment for PO {por.po_number}: {amazon_comment}")
        
        # Create work date comment for work_iwo or supply_and_fit content types
        if por.content_type in ['work_iwo', 'supply_and_fit']:
            work_date_comment = "WORK DATE CARRIED OUT TBC"
            
            # Add to work_date_comment field
            por.work_date_comment = work_date_comment
            
            logger.info(f"Added work date comment for PO {por.po_number}: {work_date_comment}")
        
        logger.info(f"🔍 Committing transaction to database")
        db_session.commit()
        logger.info(f"✅ Transaction committed successfully")
        
        # Get the PO number before closing the session
        po_number = por.po_number
        logger.info(f"✅ Database save completed successfully for PO #{po_number}")
        
        db_session.close()
        return True, ""
    except Exception as e:
        logger.error(f"❌ Database error during save: {str(e)}")
        logger.error(f"❌ Error type: {type(e).__name__}")
        import traceback
        logger.error(f"❌ Full traceback: {traceback.format_exc()}")
        try:
            db_session.rollback()
            db_session.close()
        except:
            pass
        
        # Provide specific error messages
        error_msg = str(e)
        if "UNIQUE constraint failed: por.po_number" in error_msg:
            po_number = data.get('po_number', 'unknown')
            return False, f"🚫 UPLOAD BLOCKED: PO number {po_number} already exists in this database! Duplicate PO numbers are not allowed. Please use a different PO number or contact your administrator."
        elif "UNIQUE constraint failed" in error_msg:
            return False, "🚫 UPLOAD BLOCKED: Database constraint violation. The data conflicts with existing records."
        else:
            return False, f"🚫 UPLOAD BLOCKED: Database error: {error_msg}"


def get_paginated_records(page: int, search_query: str = '') -> Tuple[List[POR], dict]:
    """
    Get paginated POR records with optional search.
    Also attaches all line items to each POR record.
    """
    try:
        from models import get_session, LineItem
        db_session = get_session()
        query = db_session.query(POR).order_by(POR.id.desc())
        if search_query:
            search_term = f"%{search_query}%"
            query = query.filter(
                POR.po_number.like(search_term) |
                POR.requestor_name.like(search_term) |
                POR.job_contract_no.like(search_term) |
                POR.op_no.like(search_term) |
                POR.description.like(search_term)
            )
        total_records = query.count()
        total_pages = (total_records + RECORDS_PER_PAGE - 1) // RECORDS_PER_PAGE
        offset = (page - 1) * RECORDS_PER_PAGE
        records = query.offset(offset).limit(RECORDS_PER_PAGE).all()
        # Attach line items to each record
        for record in records:
            record.file_count = len(record.attached_files)
            record.files = record.attached_files
            
            # Prepare attachment icons for display (max 4, one of each type)
            attachment_icons = []
            if record.attached_files:
                # Group files by type
                files_by_type = {}
                for file in record.attached_files:
                    if file.file_type not in files_by_type:
                        files_by_type[file.file_type] = []
                    files_by_type[file.file_type].append(file)
                
                # Add one icon for each file type (up to 4)
                for file_type, files in files_by_type.items():
                    if len(attachment_icons) < 4:
                        attachment_icons.append({
                            'type': file_type,
                            'count': len(files),
                            'icon': get_file_type_icon(file_type)
                        })
                
                # If we have more than 4 types, add a "+X" indicator
                if len(record.attached_files) > 4:
                    attachment_icons.append({
                        'type': 'more',
                        'count': len(record.attached_files) - 4,
                        'icon': '+'
                    })
            
            record.attachment_icons = attachment_icons
            
            # Attach all line items
            record.line_items = db_session.query(LineItem).filter_by(por_id=record.id).all()
        pagination_info = {
            'current_page': page,
            'total_pages': total_pages,
            'total_records': total_records,
            'has_prev': page > 1,
            'has_next': page < total_pages,
            'records_per_page': RECORDS_PER_PAGE
        }
        db_session.close()
        return records, pagination_info
    except Exception as e:
        logger.error(f"Error fetching records: {str(e)}")
        try:
            db_session.close()
        except:
            pass
        return [], {}


@app.route('/test')
def test():
    """Test route for debugging database and system status."""
    try:
        from models import get_session, POR, BatchCounter
        db_session = get_session()
        
        # Check database status
        total_records = db_session.query(POR).count()
        counter = db_session.query(BatchCounter).first()
        current_po = counter.value if counter else 'No counter found'
        
        # Check if tables exist
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        db_session.close()
        
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>System Status</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .status {{ padding: 10px; margin: 10px 0; border-radius: 5px; }}
                .success {{ background-color: #d4edda; color: #155724; }}
                .error {{ background-color: #f8d7da; color: #721c24; }}
                .info {{ background-color: #d1ecf1; color: #0c5460; }}
            </style>
        </head>
        <body>
            <h1>🔍 System Status Check</h1>
            
            <div class="status success">
                <h3>✅ Database Connection</h3>
                <p>Database URL: {os.environ.get('DATABASE_URL', 'sqlite:///a&p_por.db')}</p>
                <p>Tables found: {', '.join(tables) if tables else 'None'}</p>
            </div>
            
            <div class="status info">
                <h3>📊 Data Status</h3>
                <p>Total POR records: {total_records}</p>
                <p>Current PO number: {current_po}</p>
            </div>
            
            <div class="status info">
                <h3>🔗 Navigation</h3>
                <p><a href="/">📤 Upload Page</a></p>
                <p><a href="/view">👁️ View Records</a></p>
                <p><a href="/search">🔍 Search</a></p>
                <p><a href="/change-batch">🔄 Batch Change</a></p>
                <p><a href="/dashboard">📊 Dashboard</a></p>
            </div>
            
            <div class="status info">
                <h3>🧪 Test Upload</h3>
                <p><a href="/debug-upload">🔬 Debug Upload Test</a></p>
            </div>
        </body>
        </html>
        '''
    except Exception as e:
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>System Error</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .error {{ background-color: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>❌ System Error</h1>
            <div class="error">
                <p><strong>Error:</strong> {str(e)}</p>
                <p>This indicates a database connection or initialization problem.</p>
            </div>
        </body>
        </html>
        '''

@app.route('/debug-upload', methods=['GET', 'POST'])
def debug_upload():
    """Debug route to test file upload functionality."""
    if request.method == 'POST':
        try:
            file = request.files.get('file')
            if file:
                logger.info(f"DEBUG: File received - {file.filename}")
                logger.info(f"DEBUG: File type - {getattr(file, 'content_type', 'unknown')}")
                
                # Test file validation
                is_allowed = allowed_excel_file(file.filename)
                logger.info(f"DEBUG: File allowed for Excel uploader - {is_allowed}")
                
                # Test file content
                file.seek(0)
                first_bytes = file.read(8)
                file.seek(0)
                logger.info(f"DEBUG: File header - {first_bytes}")
                
                return {
                    'filename': file.filename,
                    'content_type': getattr(file, 'content_type', 'unknown'),
                    'allowed': is_allowed,
                    'header': str(first_bytes),
                    'size': len(first_bytes)
                }
            else:
                return {'error': 'No file received'}
        except Exception as e:
            return {'error': str(e)}
    
    return '''
    <html>
    <body>
        <h2>Debug Upload Test (Excel Only)</h2>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file" accept=".xlsx,.xls">
            <input type="submit" value="Test Upload">
        </form>
    </body>
    </html>
    '''




@app.route('/dashboard')
def dashboard():
    """Display the main dashboard."""
    try:
        # Use database-aware session
        current_db = get_current_database()
        db_session = get_database_session(current_db)
        
        # Get current PO from database
        counter = get_or_create_batch_counter(current_db)
        current_po_value = counter.value if counter else 1000
        
        # Get some basic stats
        total_por_count = db_session.query(POR).count()
        
        # Get company distribution stats
        a_and_p_count = db_session.query(POR).filter(POR.supplier == 'a&p').count()
        fdec_count = db_session.query(POR).filter(POR.supplier == 'FDEC').count()
        
        # Get recent activity (last 5 PORs)
        recent_activity = db_session.query(POR).order_by(POR.created_at.desc()).limit(5).all()
        
        db_session.close()
        
        # Get current database info for template
        current_db = get_current_database()
        company_info = COMPANIES.get(current_db, COMPANIES['a&p'])
        

        
        return render_template("modern_dashboard.html", 
                             current_po=current_po_value,
                             total_por_count=total_por_count,
                             a_and_p_count=a_and_p_count,
                             fdec_count=fdec_count,
                             recent_activity=recent_activity,
                             company=current_db,
                             company_info=company_info)
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        # Get current database info for template
        current_db = get_current_database()
        company_info = COMPANIES.get(current_db, COMPANIES['a&p'])
        
        return render_template("modern_dashboard.html", 
                             current_po=1000,
                             total_por_count=0,
                             a_and_p_count=0,
                             fdec_count=0,
                             recent_activity=[],
                             company=current_db,
                             company_info=company_info)


@app.route('/')
def root():
    """Redirect root to dashboard."""
    return redirect(url_for('dashboard'))


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """Handle file upload and processing."""
    if request.method == 'POST':
        try:
            file = request.files.get('file')
            logger.info(f"Upload request received. Files in request: {list(request.files.keys())}")
            
            if not file:
                logger.warning("No file found in request")
                flash("❌ No file selected", 'error')
                # Get current PO from database for template
                try:
                    current_db = get_current_database()
                    counter = get_or_create_batch_counter(current_db)
                    current_po_value = counter.value if counter else 1000
                except Exception as e:
                    logger.error(f"Error getting current PO: {str(e)}")
                    current_po_value = 1000
                
                # Get current database info for template
                current_db = get_current_database()
                company_info = COMPANIES.get(current_db, COMPANIES['a&p'])
                
                return render_template("modern_upload.html", current_po=current_po_value, company=current_db, company_info=company_info)
            
            logger.info(f"File object: {file}")
            logger.info(f"File filename: {file.filename}")
            logger.info(f"File content type: {getattr(file, 'content_type', 'unknown')}")
            logger.info(f"File content length: {getattr(file, 'content_length', 'unknown')}")
            logger.info(f"File headers: {dict(request.headers)}")
            
            # Check if file has content
            try:
                file.seek(0)
                first_bytes = file.read(100)
                file.seek(0)
                logger.info(f"First 100 bytes: {first_bytes}")
                logger.info(f"File size: {len(first_bytes)} bytes")
            except Exception as e:
                logger.error(f"Error reading file content: {str(e)}")
            
            # For main POR uploader, only allow Excel files
            if not allowed_excel_file(file.filename):
                logger.warning(f"File type not allowed for main uploader: {file.filename}")
                flash("❌ Only Excel files (.xlsx, .xls) are allowed for POR uploads", 'error')
                # Get current PO from database for template
                try:
                    current_db = get_current_database()
                    counter = get_or_create_batch_counter(current_db)
                    current_po_value = counter.value if counter else 1000
                except Exception as e:
                    logger.error(f"Error getting current PO: {str(e)}")
                    current_po_value = 1000
                
                # Get current database info for template
                current_db = get_current_database()
                company_info = COMPANIES.get(current_db, COMPANIES['a&p'])
                
                return render_template("modern_upload.html", current_po=current_po_value, company=current_db, company_info=company_info)
            
            success, message, data, line_items = process_uploaded_file(file)
            if success and data:
                # Display FDEC warning if applicable
                if data.get('fdec_warning'):
                    flash(data['fdec_warning'], 'warning')
                
                # Save to database
                save_success, save_message = save_por_to_database(data, line_items)
                if save_success:
                    # Check for batch completion after successful upload
                    try:
                        from flask import session
                        batch_end = session.get('batch_end', 0)
                        if batch_end > 0:
                            # Get current PO to check if we've reached the end
                            current_db = get_current_database()
                            counter = get_or_create_batch_counter(current_db)
                            current_po = counter.value if counter else 1000
                            
                            if current_po > batch_end:
                                batch_message = f"⚠️ BATCH COMPLETE: Reached end of batch range. Please update with more batch numbers."
                                flash(f"{message} {batch_message}", 'success')
                            else:
                                flash(message, 'success')
                        else:
                            flash(message, 'success')
                    except Exception as e:
                        logger.error(f"Error checking batch completion: {str(e)}")
                        flash(message, 'success')
                    
                    # Redirect to view the newly created POR
                    try:
                        # Get the latest POR ID to redirect to
                        current_db = get_current_database()
                        db_session = get_database_session(current_db)
                        
                        # Get database-aware models for this database
                        LocalBase, LocalPOR, LocalLineItem, LocalPORFile, LocalBatchCounter = create_database_models(current_db)
                        
                        latest_por = db_session.query(LocalPOR).order_by(LocalPOR.id.desc()).first()
                        db_session.close()
                        
                        if latest_por:
                            return redirect(url_for('view', id=latest_por.id))
                        else:
                            return redirect(url_for('view'))
                    except Exception as e:
                        logger.error(f"Error redirecting to view: {str(e)}")
                        return redirect(url_for('view'))
                else:
                    flash(save_message, 'error')
            else:
                flash(message, 'error')
        except RequestEntityTooLarge:
            flash("❌ File too large. Maximum size is 16MB.", 'error')
        except Exception as e:
            logger.error(f"Upload error: {str(e)}")
            flash(f"❌ Unexpected error: {str(e)}", 'error')
    
    # Get current PO from database for template
    try:
        current_db = get_current_database()
        counter = get_or_create_batch_counter(current_db)
        current_po_value = counter.value if counter else 1000
    except Exception as e:
        logger.error(f"Error getting current PO: {str(e)}")
        current_po_value = 1000
    
    # Get current database info for template
    current_db = get_current_database()
    company_info = COMPANIES.get(current_db, COMPANIES['a&p'])
    
    return render_template("modern_upload.html", current_po=current_po_value, company=current_db, company_info=company_info)


@app.route('/check-updates')
def check_updates():
    """Check if there are new PORs or updates available."""
    try:
        import time
        from flask import jsonify
        
        # Use database-aware session
        current_db = get_current_database()
        db_session = get_database_session(current_db)
        
        # Get the latest POR ID and count
        latest_por = db_session.query(POR).order_by(POR.id.desc()).first()
        total_count = db_session.query(POR).count()
        
        # Get the last check time from request
        last_check = request.args.get('last_check', 0, type=float)
        
        # Check if there's new data since last check
        has_new_data = False
        if latest_por:
            # Check if the latest POR was created after the last check
            if hasattr(latest_por, 'created_at') and latest_por.created_at:
                # Convert datetime to timestamp for comparison
                por_created_timestamp = latest_por.created_at.timestamp()
                has_new_data = por_created_timestamp > last_check
            else:
                # Fallback to ID comparison if no created_at field
                has_new_data = latest_por.id > int(last_check) if last_check > 0 else True
        
        db_session.close()
        
        return jsonify({
            'has_new_data': has_new_data,
            'latest_por_id': latest_por.id if latest_por else None,
            'total_count': total_count,
            'current_time': time.time()
        })
        
    except Exception as e:
        logger.error(f"Check updates error: {str(e)}")
        return jsonify({'has_new_data': False, 'error': str(e)})


@app.route('/view')
def view():
    """Display single POR record with navigation."""
    import time
    try:
        por_id = request.args.get('id', type=int)
        search_query = request.args.get('q', '').strip()
        
        # If no specific ID provided, show list of all PORs (modern view)
        if not por_id:
            # Get all PORs for the list view
            current_db = get_current_database()
            logger.info(f"[DEBUG] View route - Querying PORs from database: {current_db}")
            
            # Use database-aware session for the current database
            db_session = get_database_session(current_db)
            
            # Get database path for verification
            db_config = DATABASES.get(current_db, DATABASES['a&p'])
            db_path = db_config['path']
            import os
            abs_path = os.path.abspath(db_path)
            logger.info(f"[DEBUG] View route - Database path: {abs_path}, File exists: {os.path.exists(abs_path)}")
            
            all_pors = db_session.query(POR).order_by(POR.id.desc()).all()
            logger.info(f"[DEBUG] View route - Found {len(all_pors)} PORs in database")
            
            # Log first few PORs for debugging
            for i, por in enumerate(all_pors[:3]):
                logger.info(f"[DEBUG] POR {i+1}: ID={por.id}, PO={por.po_number}, Company={por.company}, Project={por.ship_project_name}")
            
            # Prepare POR data for the list view
            por_data = []
            for por in all_pors:
                # Get line items count
                line_items_count = db_session.query(LineItem).filter_by(por_id=por.id).count()
                
                # Get file count
                file_count = len(por.attached_files) if hasattr(por, 'attached_files') else 0
                
                por_data.append({
                    'id': por.id,
                    'po_number': por.po_number,
                    'project': por.ship_project_name or 'Unknown Project',
                    'requestor': por.requestor_name or 'Unknown',
                    'date': por.created_at.strftime('%d/%m/%Y') if por.created_at else 'Unknown',
                    'status': por.current_stage or 'received',
                    'company': por.company or current_db,
                    'line_items_count': line_items_count,
                    'file_count': file_count,
                    'order_total': float(por.order_total) if por.order_total else 0.0
                })
            
            logger.info(f"[DEBUG] View route - Prepared {len(por_data)} PORs for display")
            
            # Get current PO from database for template
            try:
                counter = get_or_create_batch_counter(current_db)
                current_po_value = counter.value if counter else 1000
            except Exception as e:
                logger.error(f"Error getting current PO: {str(e)}")
                current_po_value = 1000
            
            db_session.close()
            
            # Get current database info for template
            current_db = get_current_database()
            logger.info(f"[DEBUG] View route - Current database: {current_db}")
            company_info = COMPANIES.get(current_db, COMPANIES['a&p'])
            logger.info(f"[DEBUG] View route - Company info: {company_info['name']}")
            
            return render_template("modern_view.html", 
                                 all_pors=por_data,
                                 total_records=len(por_data),
                                 current_po=current_po_value,
                                 timestamp=int(time.time()),
                                 company=current_db,
                                 company_info=company_info)
        
        # Get the specific POR record
        current_db = get_current_database()
        db_session = get_database_session(current_db)
        
        por = db_session.query(POR).filter_by(id=por_id).first()
        if not por:
            flash("❌ PO record not found", 'error')
            return redirect(url_for('view'))
        
        # Get navigation info
        total_records = db_session.query(POR).count()
        
        # Get current position (1-based)
        current_position = db_session.query(POR).filter(POR.id <= por_id).count()
        
        # Get previous and next IDs
        prev_por = db_session.query(POR).filter(POR.id < por_id).order_by(POR.id.desc()).first()
        next_por = db_session.query(POR).filter(POR.id > por_id).order_by(POR.id.asc()).first()
        
        # Attach line items and file count
        por.line_items = db_session.query(LineItem).filter_by(por_id=por.id).all()
        por.file_count = len(por.attached_files)
        por.files = por.attached_files
        
        # Add timestamp to force cache refresh and ensure latest data
        import time
        timestamp = int(time.time())
        
        # Get current PO from database for template
        try:
            counter = get_or_create_batch_counter(current_db)
            current_po_value = counter.value if counter else 1000
        except Exception as e:
            logger.error(f"Error getting current PO: {str(e)}")
            current_po_value = 1000
        
        db_session.close()
        
        # Get current PO from database for template
        try:
            current_db = get_current_database()
            counter = get_or_create_batch_counter(current_db)
            current_po_value = counter.value if counter else 1000
        except Exception as e:
            logger.error(f"Error getting current PO: {str(e)}")
            current_po_value = 1000
        
        # Get current database info for template
        current_db = get_current_database()
        company_info = COMPANIES.get(current_db, COMPANIES['a&p'])
        
        return render_template("modern_por_detail.html", 
                             por=por,
                             prev_id=prev_por.id if prev_por else None,
                             next_id=next_por.id if next_por else None,
                             current_po=current_po_value,
                             total_records=total_records,
                             current_position=current_position,
                             timestamp=timestamp,
                             company=current_db,
                             company_info=company_info)
                             
    except Exception as e:
        logger.error(f"View error: {str(e)}")
        flash(f"❌ Error loading record: {str(e)}", 'error')
        # Get current PO from database for template
        try:
            current_db = get_current_database()
            counter = get_or_create_batch_counter(current_db)
            current_po_value = counter.value if counter else 1000
        except Exception as e:
            logger.error(f"Error getting current PO: {str(e)}")
            current_po_value = 1000
        
        # Get current database info for template
        current_db = get_current_database()
        company_info = COMPANIES.get(current_db, COMPANIES['a&p'])
        
        # For error case, always use modern_view.html since we're not showing a specific POR
        return render_template("modern_view.html", por=None, current_po=current_po_value, 
                             total_records=0, current_position=0, timestamp=int(time.time()), 
                             company=current_db, company_info=company_info)





@app.route('/search')
def search():
    """Advanced search for PO records with intelligent matching and relevance scoring."""
    try:
        search_query = request.args.get('q', '').strip()
        search_type = request.args.get('type', 'all')  # all, date, po_number, requestor, supplier
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        stage_filter = request.args.get('stage', 'all')  # all, received, sent, filed
        content_type_filter = request.args.get('content_type', 'all')  # all, work_iwo, supply_and_fit, supply
        min_amount = request.args.get('min_amount', '')
        max_amount = request.args.get('max_amount', '')
        
        if not search_query and not date_from and not date_to and stage_filter == 'all' and content_type_filter == 'all' and not min_amount and not max_amount:
            return redirect(url_for('view'))
        
        from models import get_session
        from datetime import datetime, timedelta
        from sqlalchemy import or_, and_, func, case, desc
        
        db_session = get_session()
        
        # Start with base query
        query = db_session.query(POR)
        
        # Apply filters
        filters = []
        
        # Date range filter
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d').date()
                filters.append(func.date(POR.created_at) >= from_date)
            except ValueError:
                pass
        
        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d').date()
                filters.append(func.date(POR.created_at) <= to_date)
            except ValueError:
                pass
        
        # Stage filter
        if stage_filter != 'all':
            filters.append(POR.current_stage == stage_filter)
        
        # Content type filter
        if content_type_filter != 'all':
            filters.append(POR.content_type == content_type_filter)
        
        # Amount range filter
        if min_amount:
            try:
                min_val = float(min_amount)
                filters.append(POR.order_total >= min_val)
            except ValueError:
                pass
        
        if max_amount:
            try:
                max_val = float(max_amount)
                filters.append(POR.order_total <= max_val)
            except ValueError:
                pass
        
        # Text search with intelligent matching
        if search_query:
            # Check if it's a date search
            search_date = None
            try:
                # Try UK format first (DD/MM/YYYY)
                search_date = datetime.strptime(search_query, '%d/%m/%Y').date()
            except ValueError:
                try:
                    # Try US format (YYYY-MM-DD)
                    search_date = datetime.strptime(search_query, '%Y-%m-%d').date()
                except ValueError:
                    pass
            
            if search_date:
                # Date search
                filters.append(func.date(POR.created_at) == search_date)
                search_type = 'date'
            else:
                # Text search with relevance scoring
                search_terms = search_query.split()
                search_conditions = []
                
                for term in search_terms:
                    term_pattern = f"%{term}%"
                    search_conditions.append(
                        or_(
                            POR.po_number.like(term_pattern),
                            POR.requestor_name.like(term_pattern),
                            POR.ship_project_name.like(term_pattern),
                            POR.supplier.like(term_pattern),
                            POR.job_contract_no.like(term_pattern),
                            POR.op_no.like(term_pattern),
                            POR.description.like(term_pattern),
                            POR.quote_ref.like(term_pattern),
                            POR.specification_standards.like(term_pattern),
                            POR.supplier_contact_name.like(term_pattern),
                            POR.supplier_contact_email.like(term_pattern),
                            POR.content_type.like(term_pattern)
                        )
                    )
                
                # Apply search conditions
                if search_conditions:
                    filters.append(or_(*search_conditions))
        
        # Apply all filters
        if filters:
            query = query.filter(and_(*filters))
        
        # Add relevance scoring for text searches
        if search_query and not search_date:
            # Create relevance score based on field importance and match quality
            relevance_score = case(
                (POR.po_number.like(f"%{search_query}%"), 100),  # Exact PO number match
                (POR.po_number.like(f"{search_query}%"), 90),    # PO number starts with
                (POR.requestor_name.like(f"%{search_query}%"), 80),
                (POR.ship_project_name.like(f"%{search_query}%"), 75),
                (POR.supplier.like(f"%{search_query}%"), 70),
                (POR.job_contract_no.like(f"%{search_query}%"), 65),
                (POR.op_no.like(f"%{search_query}%"), 60),
                (POR.description.like(f"%{search_query}%"), 50),
                (POR.quote_ref.like(f"%{search_query}%"), 45),
                (POR.specification_standards.like(f"%{search_query}%"), 40),
                (POR.supplier_contact_name.like(f"%{search_query}%"), 35),
                (POR.supplier_contact_email.like(f"%{search_query}%"), 30),
                (POR.content_type.like(f"%{search_query}%"), 25),
                else_=0
            )
            
            # Add relevance score to query
            query = query.add_columns(relevance_score.label('relevance_score'))
            
            # Order by relevance score (descending) then by date (newest first)
            query = query.order_by(desc('relevance_score'), desc(POR.id))
        else:
            # For date searches or filtered searches, order by date
            query = query.order_by(desc(POR.id))
        
        # Execute query
        results = query.all()
        
        # Process results
        if search_query and not search_date:
            # Extract POR objects and relevance scores
            por_results = []
            for result in results:
                if hasattr(result, 'relevance_score'):
                    por = result[0]  # First element is the POR object
                    por.relevance_score = result[1]  # Second element is the relevance score
                else:
                    por = result
                    por.relevance_score = 0
                por_results.append(por)
        else:
            por_results = results
            # Ensure all POR objects have relevance_score attribute
            for por in por_results:
                if not hasattr(por, 'relevance_score'):
                    por.relevance_score = 0
        
        # Set file count and attachment icons for each POR record
        for por in por_results:
            por.file_count = len(por.attached_files)
            
            # Prepare attachment icons for display (max 4, one of each type)
            attachment_icons = []
            if por.attached_files:
                # Group files by type
                files_by_type = {}
                for file in por.attached_files:
                    if file.file_type not in files_by_type:
                        files_by_type[file.file_type] = []
                    files_by_type[file.file_type].append(file)
                
                # Add one icon for each file type (up to 4)
                for file_type, files in files_by_type.items():
                    if len(attachment_icons) < 4:
                        attachment_icons.append({
                            'type': file_type,
                            'count': len(files),
                            'icon': get_file_type_icon(file_type)
                        })
                
                # If we have more than 4 types, add a "+X" indicator
                if len(por.attached_files) > 4:
                    attachment_icons.append({
                        'type': 'more',
                        'count': len(por.attached_files) - 4,
                        'icon': '+'
                    })
            
            por.attachment_icons = attachment_icons
        
        # Generate search statistics
        total_results = len(por_results)
        if total_results > 0:
            # Calculate statistics
            total_value = sum(por.order_total or 0 for por in por_results)
            avg_value = total_value / total_results if total_results > 0 else 0
            stages_count = {}
            for por in por_results:
                stage = por.current_stage or 'received'
                stages_count[stage] = stages_count.get(stage, 0) + 1
            
            # No flash message needed - statistics are displayed in the search summary
            
            return render_template("search_results.html", 
                                 search_query=search_query,
                                 results=por_results,
                                 search_type=search_type,
                                 total_results=total_results,
                                 total_value=total_value,
                                 avg_value=avg_value,
                                 stages_count=stages_count,
                                 filters={
                                     'date_from': date_from,
                                     'date_to': date_to,
                                     'stage': stage_filter,
                                     'content_type': content_type_filter,
                                     'min_amount': min_amount,
                                     'max_amount': max_amount
                                 })
        else:
            # No results found
            if search_date:
                flash(f"❌ No POs found for date '{search_date.strftime('%d/%m/%Y')}'", 'error')
            else:
                flash(f"❌ No PO found matching '{search_query}'", 'error')
            return redirect(url_for('view'))
        
        db_session.close()
            
    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        flash(f"❌ Error searching: {str(e)}", 'error')
        return redirect(url_for('view'))


@app.route('/change-batch', methods=['GET', 'POST'])
def change_batch():
    """Handle batch number range updates for the currently active database."""
    if request.method == 'POST':
        try:
            # Check if this is a JSON request (from frontend)
            if request.is_json:
                data = request.get_json()
                batch_range = data.get('batch_range', '')
            else:
                batch_range = request.form.get('batch_range', '').strip()
            
            logger.info(f"[DEBUG] /change-batch POST hit. batch_range: {batch_range}")
            
            if not batch_range:
                if request.is_json:
                    return jsonify({'success': False, 'error': 'Please enter a batch range'})
                else:
                    flash("❌ Please enter a batch range", 'error')
            else:
                # Parse batch range (e.g., "100-200")
                import re
                range_pattern = re.compile(r'^(\d+)-(\d+)$')
                match = range_pattern.match(batch_range)
                
                if not match:
                    if request.is_json:
                        return jsonify({'success': False, 'error': 'Invalid batch range format. Use: start-end (e.g., 100-200)'})
                    else:
                        flash("❌ Invalid batch range format. Use: start-end (e.g., 100-200)", 'error')
                else:
                    start_po = int(match.group(1))
                    end_po = int(match.group(2))
                    
                    if start_po >= end_po:
                        if request.is_json:
                            return jsonify({'success': False, 'error': 'Start number must be less than end number'})
                        else:
                            flash("❌ Start number must be less than end number", 'error')
                    else:
                        # Get the current database and update its batch counter
                        current_db = get_current_database()
                        logger.info(f"[DEBUG] Setting batch range for {current_db}: {start_po}-{end_po}")
                        
                        try:
                            # Update the batch counter for the current database
                            db_session = get_database_session(current_db)
                            logger.info(f"[DEBUG] Database session created for {current_db}")
                            
                            counter = get_or_create_batch_counter(current_db)
                            logger.info(f"[DEBUG] Batch counter retrieved: {counter.value if counter else 'None'}")
                            
                            if counter:
                                counter.value = start_po
                                db_session.commit()
                                logger.info(f"[DEBUG] Batch counter updated to {start_po}")
                            else:
                                logger.error(f"[DEBUG] Failed to get or create batch counter for {current_db}")
                                
                            db_session.close()
                        except Exception as db_error:
                            logger.error(f"[DEBUG] Database error in change-batch: {str(db_error)}")
                            if request.is_json:
                                return jsonify({'success': False, 'error': f'Database error: {str(db_error)}'})
                            else:
                                flash(f"❌ Database error: {str(db_error)}", 'error')
                            return render_template("change_batch.html", 
                                                 current_highest_po=0,
                                                 company=current_db,
                                                 company_info=COMPANIES.get(current_db, COMPANIES['a&p']))
                        
                        # Store batch information in session for tracking
                        session['batch_start'] = start_po
                        session['batch_end'] = end_po
                        session['current_batch_po'] = start_po
                        
                        if request.is_json:
                            return jsonify({
                                'success': True, 
                                'message': f'Batch range {start_po}-{end_po} started successfully for {current_db.upper()}',
                                'current_po': start_po,
                                'batch_end': end_po,
                                'database': current_db
                            })
                        else:
                            flash(f"✅ Batch range {start_po}-{end_po} started successfully for {current_db.upper()}", 'success')
                        
        except Exception as e:
            logger.error(f"Batch change error: {str(e)}")
            logger.error(f"Error type: {type(e)}")
            logger.error(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No details'}")
            if request.is_json:
                return jsonify({'success': False, 'error': f'Error updating batch: {str(e)}'})
            else:
                flash(f"❌ Error updating batch: {str(e)}", 'error')
    
    # Get current highest PO for warning display from the active database
    try:
        current_db = get_current_database()
        logger.info(f"[DEBUG] Getting highest PO for database: {current_db}")
        
        db_session = get_database_session(current_db)
        logger.info(f"[DEBUG] Database session created for highest PO query")
        
        # Test POR model access
        try:
            highest_po = db_session.query(POR).order_by(POR.po_number.desc()).first()
            logger.info(f"[DEBUG] POR query successful, highest PO: {highest_po.po_number if highest_po else 'None'}")
            current_highest_po = highest_po.po_number if highest_po else 0
        except Exception as por_error:
            logger.error(f"[DEBUG] Error querying POR table: {str(por_error)}")
            logger.error(f"[DEBUG] POR error type: {type(por_error)}")
            current_highest_po = 0
            
        db_session.close()
    except Exception as e:
        logger.error(f"Error getting highest PO: {str(e)}")
        logger.error(f"Error type: {type(e)}")
        current_highest_po = 0
    
    # Get current database info for template
    current_db = get_current_database()
    company_info = COMPANIES.get(current_db, COMPANIES['a&p'])
    
    return render_template("change_batch.html", 
                         current_highest_po=current_highest_po,
                         company=current_db,
                         company_info=company_info)


@app.route('/check-batch-status')
def check_batch_status():
    """Check current batch status and PO number for the currently active database."""
    try:
        # Get current PO from the active database
        current_db = get_current_database()
        db_session = get_database_session(current_db)
        counter = get_or_create_batch_counter(current_db)
        current_po = counter.value if counter else 1000
        db_session.close()
        
        # Get batch information from session
        batch_start = session.get('batch_start', 0)
        batch_end = session.get('batch_end', 0)
        
        # Check if we've reached the end of the batch
        batch_complete = False
        if batch_end > 0 and current_po > batch_end:
            batch_complete = True
            # Reset batch info
            session.pop('batch_start', None)
            session.pop('batch_end', None)
            session.pop('current_batch_po', None)
        
        return jsonify({
            'current_po': current_po,
            'batch_start': batch_start,
            'batch_end': batch_end,
            'batch_complete': batch_complete,
            'database': current_db
        })
        
    except Exception as e:
        logger.error(f"Error checking batch status: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/check-batch-completion')
def check_batch_completion():
    """Check if current PO has reached the end of the batch for the currently active database."""
    try:
        # Get current PO from the active database
        current_db = get_current_database()
        db_session = get_database_session(current_db)
        counter = get_or_create_batch_counter(current_db)
        current_po = counter.value if counter else 1000
        db_session.close()
        
        # Get batch information from session
        batch_start = session.get('batch_start', 0)
        batch_end = session.get('batch_end', 0)
        
        # Check if we've reached the end of the batch
        if batch_end > 0 and current_po > batch_end:
            return jsonify({
                'batch_complete': True,
                'message': f'Batch complete! Reached end of range ({batch_start}-{batch_end}). Please update with more batch numbers.',
                'current_po': current_po,
                'batch_end': batch_end,
                'database': current_db
            })
        else:
            return jsonify({
                'batch_complete': False,
                'current_po': current_po,
                'batch_end': batch_end,
                'database': current_db
            })
        
    except Exception as e:
        logger.error(f"Error checking batch completion: {str(e)}")
        return jsonify({'error': str(e)}), 500





@app.route('/attach-files/<int:por_id>', methods=['GET', 'POST'])
def attach_files(por_id):
    """Handle file attachments for POR records."""
    try:
        # Get the POR record
        from models import get_session
        db_session = get_session()
        por = db_session.query(POR).filter_by(id=por_id).first()
        
        if not por:
            flash("❌ POR record not found", 'error')
            return redirect(url_for('view'))
        
        # Get search context
        from_search = request.args.get('from_search', '')
        
        if request.method == 'POST':
            try:
                files = request.files.getlist('files')
                file_types = request.form.getlist('file_types')
                descriptions = request.form.getlist('descriptions')
                
                logger.info(f"Received {len(files)} files for upload")
                logger.info(f"File types: {file_types}")
                logger.info(f"Descriptions: {descriptions}")
                logger.info(f"All form data: {dict(request.form)}")
                logger.info(f"All files: {[f.filename for f in files if f]}")
                
                uploaded_count = 0
                for i, file in enumerate(files):
                    if file and file.filename:
                        logger.info(f"Processing file: {file.filename}")
                        logger.info(f"File extension: {file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'NO_EXTENSION'}")
                        logger.info(f"Allowed file check: {allowed_file(file.filename)}")
                        # Validate file
                        if not allowed_file(file.filename):
                            logger.warning(f"File {file.filename} not allowed")
                            continue
                        
                        # Get file info
                        file_type = file_types[i] if i < len(file_types) else 'other'
                        description = descriptions[i] if i < len(descriptions) else ''
                        
                        # Generate safe filename
                        original_filename = file.filename
                        file_extension = os.path.splitext(original_filename)[1]
                        safe_filename = f"POR_{por.po_number}_{file_type}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}{file_extension}"
                        
                        # Save file
                        file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
                        file.save(file_path)
                        logger.info(f"File saved to: {file_path}")
                        file_size = os.path.getsize(file_path)
                        logger.info(f"File size: {file_size} bytes")
                        
                        # Create PORFile record
                        por_file = PORFile(
                            por_id=por_id,
                            original_filename=original_filename,
                            stored_filename=safe_filename,
                            file_type=file_type,
                            file_size=file_size,
                            mime_type=file.content_type or 'application/octet-stream',
                            description=description
                        )
                        
                        db_session.add(por_file)
                        uploaded_count += 1
                        logger.info(f"Added file to database: {por_file.original_filename}")
                
                if uploaded_count > 0:
                    db_session.commit()
                    logger.info(f"Committed {uploaded_count} files to database")
                    
                    # Create detailed success message
                    if uploaded_count == 1:
                        flash(f"✅ Successfully uploaded 1 file", 'success')
                    else:
                        flash(f"✅ Successfully uploaded {uploaded_count} files", 'success')
                else:
                    logger.warning("No files were uploaded")
                    flash("❌ No valid files were uploaded", 'error')
                    
            except Exception as e:
                db_session.rollback()
                logger.error(f"File upload error: {str(e)}")
                flash(f"❌ Error uploading files: {str(e)}", 'error')
            finally:
                db_session.close()
        
        # Get existing attachments
        db_session = get_session()
        por = db_session.query(POR).filter_by(id=por_id).first()
        attached_files = por.attached_files if por else []
        
        # Prepare attachment icons for display (max 4, one of each type)
        attachment_icons = []
        if attached_files:
            # Group files by type
            files_by_type = {}
            for file in attached_files:
                if file.file_type not in files_by_type:
                    files_by_type[file.file_type] = []
                files_by_type[file.file_type].append(file)
            
            # Add one icon for each file type (up to 4)
            for file_type, files in files_by_type.items():
                if len(attachment_icons) < 4:
                    attachment_icons.append({
                        'type': file_type,
                        'count': len(files),
                        'icon': get_file_type_icon(file_type)
                    })
            
            # If we have more than 4 types, add a "+X" indicator
            if len(attached_files) > 4:
                attachment_icons.append({
                    'type': 'more',
                    'count': len(attached_files) - 4,
                    'icon': '+'
                })
        
        db_session.close()
        
        return render_template("modern_attach_files.html", por=por, attached_files=attached_files, attachment_icons=attachment_icons, from_search=from_search)
        
    except Exception as e:
        logger.error(f"Attach files error: {str(e)}")
        flash(f"❌ Error: {str(e)}", 'error')
        return redirect(url_for('view'))


@app.route('/view-file/<int:file_id>')
def view_file(file_id):
    """View an attached file in the browser."""
    try:
        from models import get_session
        db_session = get_session()
        por_file = db_session.query(PORFile).filter_by(id=file_id).first()
        
        if not por_file:
            flash("❌ File not found", 'error')
            return redirect(url_for('view'))
        
        file_path = os.path.join(UPLOAD_FOLDER, por_file.stored_filename)
        
        if not os.path.exists(file_path):
            flash("❌ File not found on server", 'error')
            return redirect(url_for('view'))
        
        db_session.close()
        
        # Determine MIME type based on file extension
        file_extension = por_file.original_filename.rsplit('.', 1)[1].lower() if '.' in por_file.original_filename else ''
        mime_type = 'application/octet-stream'  # default
        
        if file_extension in ['pdf']:
            mime_type = 'application/pdf'
        elif file_extension in ['jpg', 'jpeg']:
            mime_type = 'image/jpeg'
        elif file_extension in ['png']:
            mime_type = 'image/png'
        elif file_extension in ['xlsx', 'xls']:
            mime_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        elif file_extension in ['doc', 'docx']:
            mime_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        elif file_extension in ['eml']:
            mime_type = 'text/plain'  # .eml files as text
        elif file_extension in ['msg']:
            mime_type = 'application/vnd.ms-outlook'  # .msg files as Outlook format
        
        # Set headers to force inline viewing instead of download
        response = send_file(file_path, mimetype=mime_type, as_attachment=False)
        response.headers['Content-Disposition'] = f'inline; filename="{por_file.original_filename}"'
        
        # Force inline viewing for all file types
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Type'] = mime_type
        
        # Add cache control to prevent caching issues
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
        
    except Exception as e:
        logger.error(f"View file error: {str(e)}")
        flash(f"❌ Error viewing file: {str(e)}", 'error')
        return redirect(url_for('view'))


@app.route('/open-file/<int:file_id>')
def open_file(file_id):
    """Open a file with proper handling for different file types."""
    try:
        from models import get_session
        db_session = get_session()
        por_file = db_session.query(PORFile).filter_by(id=file_id).first()
        
        if not por_file:
            flash("❌ File not found", 'error')
            return redirect(url_for('view'))
        
        file_path = os.path.join(UPLOAD_FOLDER, por_file.stored_filename)
        
        if not os.path.exists(file_path):
            flash("❌ File not found on server", 'error')
            return redirect(url_for('view'))
        
        db_session.close()
        
        # Determine file type and handle accordingly
        file_extension = por_file.original_filename.rsplit('.', 1)[1].lower() if '.' in por_file.original_filename else ''
        
        # For Excel files, serve as attachment (this is the most reliable way)
        if file_extension in ['xlsx', 'xls']:
            return send_file(
                file_path, 
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=por_file.original_filename
            )
        
        # For PDF files, serve inline
        elif file_extension in ['pdf']:
            response = send_file(file_path, mimetype='application/pdf', as_attachment=False)
            response.headers['Content-Disposition'] = f'inline; filename="{por_file.original_filename}"'
            return response
        
        # For images, serve inline
        elif file_extension in ['jpg', 'jpeg', 'png']:
            mime_type = 'image/jpeg' if file_extension in ['jpg', 'jpeg'] else 'image/png'
            response = send_file(file_path, mimetype=mime_type, as_attachment=False)
            response.headers['Content-Disposition'] = f'inline; filename="{por_file.original_filename}"'
            return response
        
        # For Word documents, serve as attachment to trigger "Open with" dialog
        elif file_extension in ['doc', 'docx']:
            if file_extension == 'docx':
                mime_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            else:
                mime_type = 'application/msword'
            return send_file(
                file_path, 
                mimetype=mime_type,
                as_attachment=True,
                download_name=por_file.original_filename
            )
        
        # For email files, serve as text for .eml and attachment for .msg
        elif file_extension in ['eml', 'msg']:
            if file_extension == 'eml':
                # .eml files can be displayed as text in browser
                response = send_file(file_path, mimetype='text/plain', as_attachment=False)
                response.headers['Content-Disposition'] = f'inline; filename="{por_file.original_filename}"'
                return response
            else:
                # .msg files need to be opened with Outlook or email client
                return send_file(
                    file_path, 
                    mimetype='application/vnd.ms-outlook',
                    as_attachment=True,
                    download_name=por_file.original_filename
                )
        
        # For other files, serve as attachment (this will trigger "Open with" dialog)
        else:
            return send_file(
                file_path, 
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=por_file.original_filename
            )
        
    except Exception as e:
        logger.error(f"Open file error: {str(e)}")
        flash(f"❌ Error opening file: {str(e)}", 'error')
        return redirect(url_for('view'))


@app.route('/download-file/<int:file_id>')
def download_file(file_id):
    """Download an attached file."""
    try:
        from models import get_session
        db_session = get_session()
        por_file = db_session.query(PORFile).filter_by(id=file_id).first()
        
        if not por_file:
            flash("❌ File not found", 'error')
            return redirect(url_for('view'))
        
        file_path = os.path.join(UPLOAD_FOLDER, por_file.stored_filename)
        
        if not os.path.exists(file_path):
            flash("❌ File not found on server", 'error')
            return redirect(url_for('view'))
        
        db_session.close()
        
        return send_file(file_path, as_attachment=True, download_name=por_file.original_filename)
        
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        flash(f"❌ Error downloading file: {str(e)}", 'error')
        return redirect(url_for('view'))


@app.route('/delete-file/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    """Delete an attached file."""
    try:
        from models import get_session
        db_session = get_session()
        por_file = db_session.query(PORFile).filter_by(id=file_id).first()
        
        if not por_file:
            flash("❌ File not found", 'error')
            return redirect(url_for('view'))
        
        # Delete physical file
        file_path = os.path.join(UPLOAD_FOLDER, por_file.stored_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete database record
        db_session.delete(por_file)
        db_session.commit()
        db_session.close()
        
        flash("✅ File deleted successfully", 'success')
        
    except Exception as e:
        logger.error(f"Delete file error: {str(e)}")
        flash(f"❌ Error deleting file: {str(e)}", 'error')
    
    return redirect(request.referrer or url_for('view'))


@app.route('/delete_por', methods=['POST'])
def delete_por():
    """Delete a POR record and manage PO numbering."""
    try:
        from flask import jsonify
        from models import get_session, LineItem
        
        data = request.get_json()
        por_id = data.get('por_id')
        po_number = data.get('po_number')
        
        if not por_id or not po_number:
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        db_session = get_session()
        
        # Get the POR record
        por = db_session.query(POR).filter_by(id=por_id).first()
        if not por:
            return jsonify({'success': False, 'error': 'POR not found'})
        
        # Check if this is the latest PO number
        latest_po = db_session.query(POR).order_by(POR.po_number.desc()).first()
        is_latest = latest_po and latest_po.po_number == int(po_number)
        
        # Delete all attached files first
        for por_file in por.attached_files:
            file_path = os.path.join(UPLOAD_FOLDER, por_file.stored_filename)
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Delete all line items
        db_session.query(LineItem).filter_by(por_id=por_id).delete()
        
        # Delete the POR record
        db_session.delete(por)
        db_session.commit()

        # After deletion, set counter to the next number after the highest existing PO
        current_db = get_current_database()
        highest_po = db_session.query(POR).order_by(POR.po_number.desc()).first()
        if highest_po:
            next_po_number = highest_po.po_number
            # Update the batch counter for the current database
            counter = get_or_create_batch_counter(current_db)
            counter.value = next_po_number
            db_session.commit()
            logger.info(f"PO {po_number} deleted, counter reset to {next_po_number} (next upload will be {next_po_number + 1}) for {current_db}")
        else:
            # If no POs left, reset to starting value for the current database
            counter = get_or_create_batch_counter(current_db)
            counter.value = 1000
            db_session.commit()
            logger.info(f"All POs deleted, counter reset to starting value (1000) for {current_db}")
        db_session.close()
        
        return jsonify({
            'success': True, 
            'message': f'PO {po_number} deleted successfully',
            'was_latest': is_latest
        })
        
    except Exception as e:
        logger.error(f"Error deleting POR: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if 'db_session' in locals():
            db_session.close()


@app.route('/update_por_field', methods=['POST'])
def update_por_field():
    """Update a field in a POR record."""
    try:
        from flask import jsonify
        from models import get_session
        
        data = request.get_json()
        por_id = data.get('por_id')
        field = data.get('field')
        value = data.get('value')
        
        if not all([por_id, field, value is not None]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Validate field name to prevent SQL injection
        allowed_fields = {
            'requestor_name', 'ship_project_name', 'supplier', 'job_contract_no', 
            'op_no', 'order_total', 'quote_ref', 'quote_date', 'date_order_raised', 'date_required_by', 'show_price',
            'amazon_comment', 'work_date_comment'
        }
        
        if field not in allowed_fields:
            return jsonify({'success': False, 'error': 'Invalid field name'})
        
        # Convert value types
        if field == 'order_total':
            try:
                value = float(value) if value else 0.0
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid number format'})
        
        db_session = get_session()
        por = db_session.query(POR).filter(POR.id == por_id).first()
        
        if not por:
            return jsonify({'success': False, 'error': 'POR not found'})
        
        # Get old value before updating
        old_value = getattr(por, field)
        
        # Update the field
        setattr(por, field, value)
        
        # Add to change history
        add_change_to_history(por, field, old_value, value)
        
        db_session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error updating POR field: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if 'db_session' in locals():
            db_session.close()


@app.route('/undo_change', methods=['POST'])
def undo_change():
    """Undo the last change for a POR."""
    try:
        from flask import jsonify
        from models import get_session
        
        data = request.get_json()
        por_id = data.get('por_id')
        
        if not por_id:
            return jsonify({'success': False, 'error': 'Missing POR ID'})
        
        db_session = get_session()
        por = db_session.query(POR).filter(POR.id == por_id).first()
        
        if not por:
            return jsonify({'success': False, 'error': 'POR not found'})
        
        # Undo the change
        success, message = undo_last_change(por)
        
        if success:
            db_session.commit()
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message})
        
    except Exception as e:
        logger.error(f"Error undoing change: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if 'db_session' in locals():
            db_session.close()


@app.route('/redo_change', methods=['POST'])
def redo_change():
    """Redo the last undone change for a POR."""
    try:
        from flask import jsonify
        from models import get_session
        
        data = request.get_json()
        por_id = data.get('por_id')
        
        if not por_id:
            return jsonify({'success': False, 'error': 'Missing POR ID'})
        
        db_session = get_session()
        por = db_session.query(POR).filter(POR.id == por_id).first()
        
        if not por:
            return jsonify({'success': False, 'error': 'POR not found'})
        
        # Redo the change
        success, message = redo_last_change(por)
        
        if success:
            db_session.commit()
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message})
        
    except Exception as e:
        logger.error(f"Error redoing change: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if 'db_session' in locals():
            db_session.close()


@app.route('/update_line_item_field', methods=['POST'])
def update_line_item_field():
    """Update a field in a line item record."""
    try:
        from flask import jsonify
        from models import get_session, LineItem
        
        data = request.get_json()
        line_item_id = data.get('line_item_id')
        field = data.get('field')
        value = data.get('value')
        
        if not all([line_item_id, field, value is not None]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Validate field name to prevent SQL injection
        allowed_fields = {
            'job_contract_no', 'op_no', 'description', 'quantity', 'price_each', 'line_total'
        }
        
        if field not in allowed_fields:
            return jsonify({'success': False, 'error': 'Invalid field name'})
        
        # Convert value types
        if field in ['quantity']:
            try:
                value = int(value) if value else 0
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid number format'})
        elif field in ['price_each', 'line_total']:
            try:
                value = float(value) if value else 0.0
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid number format'})
        
        db_session = get_session()
        line_item = db_session.query(LineItem).filter(LineItem.id == line_item_id).first()
        
        if not line_item:
            return jsonify({'success': False, 'error': 'Line item not found'})
        
        # Update the field
        setattr(line_item, field, value)
        
        # Recalculate order total if price-related fields are changed
        if field in ['quantity', 'price_each', 'line_total']:
            por = db_session.query(POR).filter(POR.id == line_item.por_id).first()
            if por:
                # Calculate new total from all line items
                total = 0.0
                for item in por.line_items:
                    if item.line_total:
                        total += float(item.line_total)
                por.order_total = total
        
        db_session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error updating line item field: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if 'db_session' in locals():
            db_session.close()


@app.route('/update_timeline_stage', methods=['POST'])
def update_timeline_stage():
    """Update the timeline stage for a POR record."""
    try:
        from flask import jsonify
        from models import get_session
        from datetime import datetime, timezone
        
        data = request.get_json()
        por_id = data.get('por_id')
        new_stage = data.get('stage')
        
        if not all([por_id, new_stage]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Validate stage
        allowed_stages = ['received', 'sent', 'filed']
        if new_stage not in allowed_stages:
            return jsonify({'success': False, 'error': 'Invalid stage'})
        
        db_session = get_session()
        por = db_session.query(POR).filter(POR.id == por_id).first()
        
        if not por:
            return jsonify({'success': False, 'error': 'POR not found'})
        
        # Update stage and status color
        por.current_stage = new_stage
        por.stage_updated_at = datetime.now(timezone.utc)
        
        # Set status color based on stage
        if new_stage == 'filed':
            por.status_color = 'green'
        elif por.status_color in ['orange', 'red']:
            # Keep existing color if it's orange or red
            pass
        else:
            por.status_color = 'normal'
        
        db_session.commit()
        
        return jsonify({
            'success': True, 
            'stage': new_stage,
            'status_color': por.status_color
        })
        
    except Exception as e:
        logger.error(f"Error updating timeline stage: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if 'db_session' in locals():
            db_session.close()


@app.route('/add_timeline_comment', methods=['POST'])
def add_timeline_comment():
    """Add a comment to a specific timeline stage."""
    try:
        from flask import jsonify
        from models import get_session
        from datetime import datetime, timezone
        
        data = request.get_json()
        por_id = data.get('por_id')
        stage = data.get('stage')
        comment = data.get('comment')
        status_color = data.get('status_color', 'normal')
        
        if not all([por_id, stage, comment]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Validate stage
        allowed_stages = ['received', 'sent', 'filed']
        if stage not in allowed_stages:
            return jsonify({'success': False, 'error': 'Invalid stage'})
        
        # Validate status color
        allowed_colors = ['normal', 'orange', 'red']
        if status_color not in allowed_colors:
            return jsonify({'success': False, 'error': 'Invalid status color'})
        
        db_session = get_session()
        por = db_session.query(POR).filter(POR.id == por_id).first()
        
        if not por:
            return jsonify({'success': False, 'error': 'POR not found'})
        
        # Add timestamp to comment
        timestamp = datetime.now(timezone.utc).strftime('%d/%m/%Y %H:%M')
        formatted_comment = f"[{timestamp}] {comment}"
        
        # Update the appropriate comment field
        if stage == 'received':
            existing = por.received_comments or ""
            por.received_comments = f"{existing}\n{formatted_comment}".strip()
        elif stage == 'sent':
            existing = por.sent_comments or ""
            por.sent_comments = f"{existing}\n{formatted_comment}".strip()
        elif stage == 'filed':
            existing = por.filed_comments or ""
            por.filed_comments = f"{existing}\n{formatted_comment}".strip()
        
        # Update status color if specified
        if status_color != 'normal':
            por.status_color = status_color
        
        db_session.commit()
        
        return jsonify({
            'success': True,
            'comment': formatted_comment,
            'status_color': por.status_color
        })
        
    except Exception as e:
        logger.error(f"Error adding timeline comment: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if 'db_session' in locals():
            db_session.close()


@app.route('/delete_timeline_comment', methods=['POST'])
def delete_timeline_comment():
    """Delete a comment from a specific timeline stage."""
    try:
        from flask import jsonify
        from models import get_session
        
        data = request.get_json()
        por_id = data.get('por_id')
        stage = data.get('stage')
        
        if not all([por_id, stage]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Validate stage
        allowed_stages = ['received', 'sent', 'filed']
        if stage not in allowed_stages:
            return jsonify({'success': False, 'error': 'Invalid stage'})
        
        db_session = get_session()
        por = db_session.query(POR).filter(POR.id == por_id).first()
        
        if not por:
            return jsonify({'success': False, 'error': 'POR not found'})
        
        # Clear the appropriate comment field
        if stage == 'received':
            por.received_comments = None
        elif stage == 'sent':
            por.sent_comments = None
        elif stage == 'filed':
            por.filed_comments = None
        
        db_session.commit()
        
        return jsonify({
            'success': True,
            'message': f'{stage.capitalize()} comment deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Error deleting timeline comment: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if 'db_session' in locals():
            db_session.close()


@app.route('/update_order_type', methods=['POST'])
def update_order_type():
    """Update the order type for a POR record."""
    try:
        from flask import jsonify
        from models import get_session
        
        data = request.get_json()
        por_id = data.get('por_id')
        order_type = data.get('order_type')
        
        if not all([por_id, order_type]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Validate order type
        allowed_types = ['new', 'revised', 'cancelled']
        if order_type not in allowed_types:
            return jsonify({'success': False, 'error': 'Invalid order type'})
        
        db_session = get_session()
        por = db_session.query(POR).filter(POR.id == por_id).first()
        
        if not por:
            return jsonify({'success': False, 'error': 'POR not found'})
        
        # Update order type
        por.order_type = order_type
        db_session.commit()
        
        return jsonify({
            'success': True, 
            'order_type': order_type
        })
        
    except Exception as e:
        logger.error(f"Error updating order type: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if 'db_session' in locals():
            db_session.close()


@app.route('/update_content_type', methods=['POST'])
def update_content_type():
    """Update the content type for a POR record."""
    try:
        from flask import jsonify
        from models import get_session
        
        data = request.get_json()
        por_id = data.get('por_id')
        content_type = data.get('content_type')
        
        if not all([por_id, content_type]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Validate content type
        allowed_types = ['work_iwo', 'supply_and_fit', 'supply']
        if content_type not in allowed_types:
            return jsonify({'success': False, 'error': 'Invalid content type'})
        
        db_session = get_session()
        por = db_session.query(POR).filter(POR.id == por_id).first()
        
        if not por:
            return jsonify({'success': False, 'error': 'POR not found'})
        
        # Update content type
        por.content_type = content_type
        
        # Handle work date comment based on content type change
        if content_type in ['work_iwo', 'supply_and_fit']:
            # Create work date comment for work_iwo or supply_and_fit
            work_date_comment = "WORK DATE CARRIED OUT TBC"
            por.work_date_comment = work_date_comment
            logger.info(f"Added work date comment for PO {por.po_number} after content type change: {work_date_comment}")
        else:
            # Remove work date comment for supply and other content types
            por.work_date_comment = None
            logger.info(f"Removed work date comment for PO {por.po_number} after content type change to {content_type}")
        
        db_session.commit()
        
        return jsonify({
            'success': True, 
            'content_type': content_type
        })
        
    except Exception as e:
        logger.error(f"Error updating content type: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if 'db_session' in locals():
            db_session.close()


@app.route('/attach_email/<int:por_id>', methods=['POST'])
def attach_email_to_por(por_id):
    """Attach an email file to a specific POR record."""
    try:
        from flask import jsonify
        from models import get_session
        
        # Get the POR record
        db_session = get_session()
        por = db_session.query(POR).filter(POR.id == por_id).first()
        
        if not por:
            return jsonify({'success': False, 'error': 'POR not found'})
        
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        # Validate file type
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'error': 'Invalid file type. Only .msg and .eml files are allowed'})
        
        # Check file extension
        file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if file_extension not in ['msg', 'eml']:
            return jsonify({'success': False, 'error': 'Only email files (.msg, .eml) are allowed'})
        
        # Generate safe filename with PO number
        original_filename = file.filename
        file_extension = os.path.splitext(original_filename)[1]
        safe_filename = f"POR_{por.po_number}_EMAIL_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}{file_extension}"
        
        # Save file
        file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
        file.save(file_path)
        file_size = os.path.getsize(file_path)
        
        # Parse email content for description
        file.seek(0)
        email_description = "Email attachment"
        
        try:
            import email
            from email import policy
            
            if file_extension == '.eml':
                msg = email.message_from_file(file, policy=policy.default)
                subject = msg.get('subject', 'No Subject')
                from_header = msg.get('from', 'Unknown Sender')
                email_description = f"Email: {subject} (from {from_header})"
            else:
                email_description = f"Outlook Message: {original_filename}"
        except:
            email_description = f"Email: {original_filename}"
        
        # Create PORFile record
        por_file = PORFile(
            por_id=por_id,
            original_filename=original_filename,
            stored_filename=safe_filename,
            file_type='email',
            file_size=file_size,
            mime_type='message/rfc822' if file_extension == '.eml' else 'application/vnd.ms-outlook',
            description=email_description
        )
        
        db_session.add(por_file)
        db_session.commit()
        db_session.close()
        
        return jsonify({
            'success': True, 
            'message': f'Email attached to PO #{por.po_number}',
            'file_id': por_file.id,
            'filename': original_filename
        })
        
    except Exception as e:
        logger.error(f"Error attaching email: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if 'db_session' in locals():
            db_session.close()


@app.route('/delete_line_item/<int:line_item_id>', methods=['DELETE'])
def delete_line_item(line_item_id):
    """Delete a specific line item from a POR record."""
    try:
        from flask import jsonify
        from models import get_session, LineItem
        
        db_session = get_session()
        line_item = db_session.query(LineItem).filter(LineItem.id == line_item_id).first()
        
        if not line_item:
            return jsonify({'success': False, 'error': 'Line item not found'})
        
        # Store some info for the response
        line_description = line_item.description or 'this line item'
        por_id = line_item.por_id
        
        # Delete the line item
        db_session.delete(line_item)
        
        # Recalculate order total after deletion
        por = db_session.query(POR).filter(POR.id == por_id).first()
        if por:
            # Calculate new total from remaining line items
            total = 0.0
            for item in por.line_items:
                if item.line_total:
                    total += float(item.line_total)
            por.order_total = total
        
        db_session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Line item "{line_description}" deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Error deleting line item: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if 'db_session' in locals():
            db_session.close()


@app.route('/add_line_item', methods=['POST'])
def add_line_item():
    """Add a new line item to a POR record."""
    try:
        from flask import jsonify
        from models import get_session, LineItem
        
        data = request.get_json()
        por_id = data.get('por_id')
        
        if not por_id:
            return jsonify({'success': False, 'error': 'Missing POR ID'})
        
        db_session = get_session()
        
        # Verify the POR exists
        por = db_session.query(POR).filter(POR.id == por_id).first()
        if not por:
            return jsonify({'success': False, 'error': 'POR not found'})
        
        # Create new line item with empty values
        new_line_item = LineItem(
            por_id=por_id,
            job_contract_no='',
            op_no='',
            description='',
            quantity=0,
            price_each=0.0,
            line_total=0.0
        )
        
        db_session.add(new_line_item)
        db_session.commit()
        
        return jsonify({
            'success': True,
            'line_item_id': new_line_item.id,
            'message': 'New line item added successfully'
        })
        
    except Exception as e:
        logger.error(f"Error adding line item: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if 'db_session' in locals():
            db_session.close()


# Register custom Jinja2 filters
app.jinja_env.filters['clean_query_string'] = clean_query_string


@app.route('/api/pors')
def api_get_pors():
    """API endpoint to get PORs data for the modern view page."""
    try:
        from models import get_session, LineItem
        from sqlalchemy import desc
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        page_size = request.args.get('page_size', 10, type=int)
        search_query = request.args.get('search', '').strip()
        status_filter = request.args.get('status', 'all')
        company_filter = request.args.get('company', 'all')
        date_filter = request.args.get('date', '')
        
        db_session = get_session()
        
        # Start with base query
        query = db_session.query(POR)
        
        # Apply filters
        if search_query:
            search_pattern = f"%{search_query}%"
            query = query.filter(
                db_session.query(POR).filter(
                    db_session.or_(
                        POR.po_number.like(search_pattern),
                        POR.requestor_name.like(search_pattern),
                        POR.ship_project_name.like(search_pattern),
                        POR.supplier.like(search_pattern)
                    )
                ).exists()
            )
        
        if status_filter != 'all':
            query = query.filter(POR.current_stage == status_filter)
        
        if company_filter != 'all':
            query = query.filter(POR.company == company_filter)
        
        if date_filter:
            try:
                from datetime import datetime, timedelta
                today = datetime.now().date()
                
                if date_filter == 'today':
                    query = query.filter(db_session.func.date(POR.created_at) == today)
                elif date_filter == 'week':
                    week_ago = today - timedelta(days=7)
                    query = query.filter(db_session.func.date(POR.created_at) >= week_ago)
                elif date_filter == 'month':
                    month_ago = today - timedelta(days=30)
                    query = query.filter(db_session.func.date(POR.created_at) >= month_ago)
                elif date_filter == 'quarter':
                    quarter_ago = today - timedelta(days=90)
                    query = query.filter(db_session.func.date(POR.created_at) >= quarter_ago)
            except Exception as e:
                logger.error(f"Date filter error: {str(e)}")
        
        # Get total count before pagination
        total_count = query.count()
        
        # Apply pagination
        offset = (page - 1) * page_size
        pors = query.order_by(desc(POR.id)).offset(offset).limit(page_size).all()
        
        # Prepare response data
        por_data = []
        for por in pors:
            # Get line items count
            line_items_count = db_session.query(LineItem).filter_by(por_id=por.id).count()
            
            # Get file count
            file_count = len(por.attached_files) if hasattr(por, 'attached_files') else 0
            
            por_data.append({
                'id': por.id,
                'po_number': por.po_number,
                'project': por.ship_project_name or 'Unknown Project',
                'requestor': por.requestor_name or 'Unknown',
                'date': por.created_at.strftime('%d/%m/%Y') if por.created_at else 'Unknown',
                'status': por.current_stage or 'received',
                'company': por.company or 'a&p',
                'line_items_count': line_items_count,
                'file_count': file_count,
                'order_total': float(por.order_total) if por.order_total else 0.0
            })
        
        db_session.close()
        
        # Calculate pagination info
        total_pages = (total_count + page_size - 1) // page_size
        
        return jsonify({
            'success': True,
            'data': por_data,
            'pagination': {
                'current_page': page,
                'page_size': page_size,
                'total_pages': total_pages,
                'total_count': total_count
            }
        })
        
    except Exception as e:
        logger.error(f"API get PORs error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/get-content-type-classification/<int:line_item_id>')
def get_content_type_classification(line_item_id):
    """Get the current content type classification for a line item."""
    try:
        from models import get_session, LineItem
        
        db_session = get_session()
        line_item = db_session.query(LineItem).filter(LineItem.id == line_item_id).first()
        
        if not line_item:
            return jsonify({
                'status': 'error',
                'message': 'Line item not found'
            }), 404
        
        # Get the POR record
        por = db_session.query(POR).filter(POR.id == line_item.por_id).first()
        if not por:
            return jsonify({
                'status': 'error',
                'message': 'POR record not found'
            }), 404
        
        # Get current content type
        current_content_type = por.content_type or 'supply'
        
        db_session.close()
        
        return jsonify({
            'status': 'success',
            'line_item_id': line_item_id,
            'description': line_item.description or '',
            'current_content_type': current_content_type,
            'suggestion': 'Content type is determined by rule-based pattern matching'
        })
        
    except Exception as e:
        logger.error(f"Error getting content type classification: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error getting classification: {str(e)}'
        }), 500


@app.route('/api/update-por-field', methods=['POST'])
def api_update_por_field():
    """API endpoint to update a field in a POR record for the modern interface."""
    try:
        from models import get_session
        
        data = request.get_json()
        por_id = data.get('por_id')
        field_name = data.get('field_name')
        new_value = data.get('new_value')
        
        if not all([por_id, field_name, new_value is not None]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Validate field name to prevent SQL injection
        allowed_fields = {
            'ship_project_name', 'requestor_name', 'description', 'current_stage', 'content_type', 'order_type', 'supplier'
        }
        
        if field_name not in allowed_fields:
            return jsonify({'success': False, 'error': 'Invalid field name'})
        
        db_session = get_session()
        por = db_session.query(POR).filter(POR.id == por_id).first()
        
        if not por:
            return jsonify({'success': False, 'error': 'POR not found'})
        
        # Handle different field types
        if field_name == 'description':
            # This is for line item descriptions - need to handle differently
            # For now, return error as this needs line item ID
            return jsonify({'success': False, 'error': 'Line item updates not yet implemented'})
        else:
            # Update POR field
            old_value = getattr(por, field_name, None)
            setattr(por, field_name, new_value)
            
            # Log the change
            logger.info(f"Updated POR {por_id} field {field_name} from '{old_value}' to '{new_value}'")
        
        db_session.commit()
        db_session.close()
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"API update POR field error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/update-line-item-description', methods=['POST'])
def api_update_line_item_description():
    """API endpoint to update a line item description."""
    try:
        from models import get_session, LineItem
        
        data = request.get_json()
        line_item_id = data.get('line_item_id')
        new_description = data.get('new_description')
        
        if not all([line_item_id, new_description is not None]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        db_session = get_session()
        line_item = db_session.query(LineItem).filter(LineItem.id == line_item_id).first()
        
        if not line_item:
            return jsonify({'success': False, 'error': 'Line item not found'})
        
        # Update the description
        old_description = line_item.description
        line_item.description = new_description
        
        # Log the change
        logger.info(f"Updated line item {line_item_id} description from '{old_description}' to '{new_description}'")
        
        db_session.commit()
        db_session.close()
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"API update line item description error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/create-line-item', methods=['POST'])
def api_create_line_item():
    """API endpoint to create a new line item."""
    try:
        from models import get_session, LineItem
        
        data = request.get_json()
        por_id = data.get('por_id')
        description = data.get('description')
        quantity = data.get('quantity', 1)
        unit_price = data.get('unit_price', 0.00)
        
        if not all([por_id, description]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        db_session = get_session()
        
        # Create new line item
        new_line_item = LineItem(
            por_id=por_id,
            description=description,
            quantity=quantity,
            unit_price=unit_price
        )
        
        db_session.add(new_line_item)
        
        # Log the creation
        logger.info(f"Created new line item for POR {por_id}: {description}")
        
        db_session.commit()
        db_session.close()
        
        return jsonify({'success': True, 'line_item_id': new_line_item.id})
        
    except Exception as e:
        logger.error(f"API create line item error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors."""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    from models import get_session
    db_session = get_session()
    try:
        db_session.rollback()
    except:
        pass
    finally:
        db_session.close()
    return render_template('500.html'), 500


@app.route('/analytics')
def analytics():
    """Display comprehensive POR analytics and breakdowns."""
    try:
        from sqlalchemy import func, extract
        from datetime import datetime, timedelta
        
        # Use database-aware session
        current_db = get_current_database()
        db_session = get_database_session(current_db)
        
        # Get total counts and values
        total_pors = db_session.query(POR).count()
        total_value = db_session.query(func.sum(POR.order_total)).scalar() or 0
        
        # Get status distribution
        status_counts = db_session.query(
            POR.current_stage, 
            func.count(POR.id)
        ).group_by(POR.current_stage).all()
        
        status_labels = [status or 'Unknown' for status, _ in status_counts]
        status_data = [count for _, count in status_counts]
        
        # Get content type distribution
        content_type_counts = db_session.query(
            POR.content_type, 
            func.count(POR.id)
        ).group_by(POR.content_type).all()
        
        content_type_labels = [ct or 'Unknown' for ct, _ in content_type_counts]
        content_type_data = [count for _, count in content_type_counts]
        
        # Get top suppliers by value
        top_suppliers = db_session.query(
            POR.supplier,
            func.sum(POR.order_total).label('total_value')
        ).filter(
            POR.supplier.isnot(None),
            POR.order_total.isnot(None)
        ).group_by(POR.supplier).order_by(
            func.sum(POR.order_total).desc()
        ).limit(5).all()
        
        top_suppliers_data = [
            {'name': supplier, 'total_value': float(total_value)}
            for supplier, total_value in top_suppliers
        ]
        
        # Get top requestors by count
        top_requestors = db_session.query(
            POR.requestor_name,
            func.count(POR.id).label('count')
        ).filter(
            POR.requestor_name.isnot(None)
        ).group_by(POR.requestor_name).order_by(
            func.count(POR.id).desc()
        ).limit(5).all()
        
        top_requestors_data = [
            {'name': requestor, 'count': count}
            for requestor, count in top_requestors
        ]
        
        # Get monthly trends (last 12 months)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=365)
        
        monthly_data = db_session.query(
            extract('year', POR.created_at).label('year'),
            extract('month', POR.created_at).label('month'),
            func.count(POR.id).label('count'),
            func.sum(POR.order_total).label('total_value')
        ).filter(
            POR.created_at >= start_date
        ).group_by(
            extract('year', POR.created_at),
            extract('month', POR.created_at)
        ).order_by(
            extract('year', POR.created_at),
            extract('month', POR.created_at)
        ).all()
        
        # Process monthly data
        monthly_labels = []
        monthly_counts = []
        monthly_values = []
        
        for year, month, count, total_value in monthly_data:
            month_name = datetime(year, month, 1).strftime('%b %Y')
            monthly_labels.append(month_name)
            monthly_counts.append(count)
            monthly_values.append(float(total_value or 0))
        
        # Calculate active and completed PORs
        active_pors = db_session.query(POR).filter(
            POR.current_stage.in_(['received', 'sent'])
        ).count()
        
        completed_pors = db_session.query(POR).filter(
            POR.current_stage == 'filed'
        ).count()
        
        db_session.close()
        
        # Get current database info for template
        current_db = get_current_database()
        company_info = COMPANIES.get(current_db, COMPANIES['a&p'])
        
        return render_template('analytics.html',
                             total_pors=total_pors,
                             total_value=total_value,
                             active_pors=active_pors,
                             completed_pors=completed_pors,
                             status_labels=status_labels,
                             status_data=status_data,
                             content_type_labels=content_type_labels,
                             content_type_data=content_type_data,
                             top_suppliers=top_suppliers_data,
                             top_requestors=top_requestors_data,
                             monthly_labels=monthly_labels,
                             monthly_data=monthly_counts,
                             monthly_values=monthly_values,
                             company=current_db,
                             company_info=company_info)
        
    except Exception as e:
        logger.error(f"Analytics error: {str(e)}")
        flash('Error loading analytics data', 'error')
        return redirect(url_for('dashboard'))


@app.route('/switch_database', methods=['POST'])
def switch_database():
    """Switch between A&P and FDEC databases."""
    try:
        data = request.get_json()
        new_database = data.get('database')
        
        logger.info(f"[DEBUG] Switching database from {get_current_database()} to {new_database}")
        logger.info(f"[DEBUG] Session before switch: {dict(session)}")
        
        if new_database not in DATABASES:
            logger.error(f"Invalid database specified: {new_database}")
            return jsonify({'success': False, 'error': 'Invalid database specified'}), 400
        
        # Store the selected database in session
        session['current_database'] = new_database
        
        # Force session to be saved
        session.modified = True
        
        # Verify the session was updated
        current_db = get_current_database()
        logger.info(f"[DEBUG] Session after switch: {dict(session)}")
        logger.info(f"[DEBUG] Session updated. Current database is now: {current_db}")
        
        # Initialize the new database if it doesn't exist
        engine = get_database_engine(new_database)
        
        # Get database-aware models for this database
        LocalBase, LocalPOR, LocalLineItem, LocalPORFile, LocalBatchCounter = create_database_models(new_database)
        
        # Create all tables in this database
        LocalBase.metadata.create_all(engine)
        
        # Test the database connection
        test_session = get_database_session(new_database)
        por_count = test_session.query(LocalPOR).count()
        test_session.close()
        
        logger.info(f"Successfully switched to {new_database} database. Found {por_count} PORs.")
        
        return jsonify({
            'success': True, 
            'message': f'Switched to {DATABASES[new_database]["display_name"]}',
            'database': new_database,
            'por_count': por_count
        })
        
    except Exception as e:
        logger.error(f"Database switch error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/get_database_info')
def get_database_info():
    """Get information about the current database."""
    try:
        current_db = get_current_database()
        db_config = DATABASES[current_db]
        
        # Get database statistics
        engine = get_database_engine(current_db)
        db_session = get_database_session(current_db)
        
        total_pors = db_session.query(POR).count()
        total_value = db_session.query(func.sum(POR.order_total)).scalar() or 0
        
        db_session.close()
        
        return jsonify({
            'success': True,
            'current_database': current_db,
            'display_name': db_config['display_name'],
            'total_pors': total_pors,
            'total_value': float(total_value)
        })
        
    except Exception as e:
        logger.error(f"Database info error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/update_company', methods=['POST'])
def update_company():
    """Update the company for a POR record."""
    try:
        from flask import jsonify
        from models import get_session
        
        data = request.get_json()
        por_id = data.get('por_id')
        company = data.get('company')
        
        if not all([por_id, company]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Validate company
        allowed_companies = ['a&p', 'fdec']
        if company not in allowed_companies:
            return jsonify({'success': False, 'error': 'Invalid company'})
        
        db_session = get_session()
        por = db_session.query(POR).filter(POR.id == por_id).first()
        
        if not por:
            return jsonify({'success': False, 'error': 'POR not found'})
        
        # Update company
        por.company = company
        db_session.commit()
        
        return jsonify({
            'success': True, 
            'company': company
        })
        
    except Exception as e:
        logger.error(f"Error updating company: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if 'db_session' in locals():
            db_session.close()


@app.route('/debug_database_status')
def debug_database_status():
    """Debug route to check current database status and session."""
    try:
        current_db = get_current_database()
        session_data = dict(session)
        
        # Get database info
        db_config = DATABASES.get(current_db, DATABASES['a&p'])
        
        # Test database connection
        engine = get_database_engine(current_db)
        db_session = get_database_session(current_db)
        por_count = db_session.query(POR).count()
        db_session.close()
        
        return jsonify({
            'success': True,
            'current_database': current_db,
            'session_data': session_data,
            'database_config': db_config,
            'por_count': por_count,
            'session_id': session.sid if hasattr(session, 'sid') else 'No SID'
        })
        
    except Exception as e:
        logger.error(f"Debug database status error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/test_database')
def test_database():
    """Test route to verify database switching and show current database contents."""
    try:
        current_db = get_current_database()
        logger.info(f"[DEBUG] Test route - Current database: {current_db}")
        
        # Get database session
        db_session = get_database_session(current_db)
        
        # Count PORs
        por_count = db_session.query(POR).count()
        
        # Get sample PORs
        sample_pors = db_session.query(POR).limit(5).all()
        
        # Get database file info
        import os
        db_config = DATABASES.get(current_db, DATABASES['a&p'])
        db_path = db_config['path']
        file_exists = os.path.exists(db_path)
        file_size = os.path.getsize(db_path) if file_exists else 0
        
        db_session.close()
        
        return jsonify({
            'success': True,
            'current_database': current_db,
            'database_path': db_path,
            'file_exists': file_exists,
            'file_size': file_size,
            'por_count': por_count,
            'sample_pors': [
                {
                    'id': por.id,
                    'po_number': por.po_number,
                    'company': por.company,
                    'project': por.ship_project_name
                } for por in sample_pors
            ]
        })
        
    except Exception as e:
        logger.error(f"Test database error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


def check_fdec_job_warning(job_contract_no, current_database: str) -> Optional[str]:
    """
    Check if a job number starting with 6 is being uploaded to A&P database.
    Returns warning message if applicable, None otherwise.
    """
    if not job_contract_no:
        return None
    
    # Convert to string if it's not already
    job_str = str(job_contract_no)
    
    # Check if job number starts with 6 and is being uploaded to A&P
    if job_str.startswith('6') and current_database == 'a&p':
        return "⚠️ WARNING: This POR contains job numbers starting with '6' which indicates it is for FDEC. Please ensure you are uploading to the correct database."
    
    return None


def check_batch_number_conflict(po_number: int, current_database: str) -> Optional[str]:
    """
    Check if a batch number is being used across different company databases.
    Returns error message if there's a conflict, None otherwise.
    """
    try:
        # Check if this PO number exists in the other database
        other_database = 'fdec' if current_database == 'a&p' else 'a&p'
        
        # Get database session for the other database
        other_db_session = get_database_session(other_database)
        
        # Get database-aware models for the other database
        LocalBase, LocalPOR, LocalLineItem, LocalPORFile, LocalBatchCounter = create_database_models(other_database)
        
        # Check if PO number exists in other database using the correct model
        existing_por = other_db_session.query(LocalPOR).filter_by(po_number=po_number).first()
        other_db_session.close()
        
        if existing_por:
            company_name = "FDEC" if other_database == 'fdec' else "A&P"
            current_company = "FDEC" if current_database == 'fdec' else "A&P"
            return f"🚫 UPLOAD BLOCKED: PO number {po_number} is already in use in the {company_name} database! You cannot use the same PO number in both {current_company} and {company_name} databases. Please use a different PO number or contact your administrator."
        
        return None
        
    except Exception as e:
        logger.error(f"Error checking batch number conflict: {str(e)}")
        return None


@app.route('/company-management')
def company_management():
    """Company and supplier management interface."""
    try:
        current_db = get_current_database()
        company_info = COMPANIES.get(current_db, COMPANIES['a&p'])
        
        # Get statistics for both databases
        a_and_p_session = get_database_session('a&p')
        fdec_session = get_database_session('fdec')
        
        # Get POR counts for each company
        a_and_p_count = a_and_p_session.query(POR).count()
        fdec_count = fdec_session.query(POR).count()
        
        # Get supplier statistics
        a_and_p_suppliers = a_and_p_session.query(POR.supplier, func.count(POR.id)).group_by(POR.supplier).all()
        fdec_suppliers = fdec_session.query(POR.supplier, func.count(POR.id)).group_by(POR.supplier).all()
        
        a_and_p_session.close()
        fdec_session.close()
        
        return render_template("company_management.html", 
                             company=current_db,
                             company_info=company_info,
                             a_and_p_count=a_and_p_count,
                             fdec_count=fdec_count,
                             a_and_p_suppliers=a_and_p_suppliers,
                             fdec_suppliers=fdec_suppliers)
                             
    except Exception as e:
        logger.error(f"Company management error: {str(e)}")
        flash(f"❌ Error loading company management: {str(e)}", 'error')
        return redirect(url_for('dashboard'))





if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
