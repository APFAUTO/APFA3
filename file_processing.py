
import os
import logging

# Setup logging
logger = logging.getLogger(__name__)

import re
from datetime import datetime, timezone
from typing import Optional, Tuple
from werkzeug.utils import secure_filename

from database import get_current_database
from batch_number_manager import increment_batch_number
from company_config import get_company_config
from utils import read_ws, extract_por_data_by_map, extract_line_items_by_map, get_order_total_by_map, to_float, capitalize_text, allowed_excel_file



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
            return False, "Only Excel-compatible files are allowed for POR uploads. Supported formats: .xlsx, .xls, .xlsm, .xlsb, .xltx, .xltm, .xlt, .xlm, .xla, .xlw, .ods, .csv, .xml", None, None
        
        # Check file extension
        file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        logger.info(f"File extension detected: {file_extension}")
        
        
        
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
        
        # Generate PO number using new robust batch number manager
        current_db = get_current_database()
        po_number = increment_batch_number(current_db)
        
        date_order = por_data.get('date_order_raised', datetime.now().strftime('%d/%m/%Y'))
        requestor = por_data.get('requestor_name', 'Unknown')
        
        company_config = get_company_config(current_db)
        upload_folder = company_config.upload_folder
        os.makedirs(upload_folder, exist_ok=True)

        # Preserve original file extension
        original_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'xlsx'
        safe_filename = secure_filename(f'PO_{po_number}_{date_order}_{requestor.replace(" ", "_")}.{original_extension}')
        
        # Save file locally
        try:
            file.seek(0)
            file_path = os.path.join(upload_folder, safe_filename)
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
        fdec_warning = company_config.check_fdec_warning(first_item.get('job'))
        
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
        current_db = get_current_database()
        po_number = increment_batch_number(current_db)
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
