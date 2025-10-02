import logging

# Setup logging
logger = logging.getLogger(__name__)

from typing import List, Tuple
from flask import session
from config import CURRENT_DATABASE
from database_managers import get_database_manager
from utils import to_float, detect_content_type_from_line_items, detect_content_type_from_line_items

RECORDS_PER_PAGE = 10

def get_current_database():
    """Get the current active database from session or default."""
    current_db = session.get('current_database', CURRENT_DATABASE)
    logger.info(f"[DEBUG] get_current_database() - Session value: {session.get('current_database')}, Default: {CURRENT_DATABASE}, Returning: {current_db}")
    return current_db

def save_por_to_database(data: dict, line_items: list = None) -> Tuple[bool, str]:
    """Save POR data and its line items to database."""
    try:
        import re
        
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)
        
        with db_manager.session_scope() as db_session:
            logger.info(f"🔍 Starting database save for PO #{data.get('po_number')} in database: {current_db}")
            
            por = db_manager.POR(**data)
            db_session.add(por)
            db_session.flush()  # Get POR id
            logger.info(f"✅ POR created with ID: {por.id}")
            
            # Save line items if provided
            if line_items:
                logger.info(f"🔍 Saving {len(line_items)} line items")
                for i, item in enumerate(line_items):
                    line_item = db_manager.LineItem(
                        por_id=por.id,
                        job_contract_no=str(item.get('job')) if item.get('job') is not None else '',
                        op_no=str(item.get('op')) if item.get('op') is not None else '',
                        description=str(item.get('desc')) if item.get('desc') is not None else '',
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
            # db_session.commit() is handled by the context manager
            logger.info(f"✅ Transaction committed successfully")
            
            # Get the PO number before closing the session
            po_number = por.po_number
            logger.info(f"✅ Database save completed successfully for PO #{po_number}")
            
            # db_session.close() is handled by the context manager
            return True, ""
    except IntegrityError as ie: # Catch IntegrityError specifically
        logger.error(f"❌ Integrity error during save: {str(ie)}")
        logger.error(f"❌ Full traceback: {traceback.format_exc()}")
        
        if "UNIQUE constraint failed: por.po_number" in str(ie):
            # Custom message for duplicate PO number
            po_number = data.get('po_number', 'Unknown')
            detailed_error = f"Database error: {str(ie)}"
            return False, f"Duplicate PO Number: PO #{po_number} already exists. Please use a different PO number or check existing records. <details><summary>Show detailed error</summary><pre>{detailed_error}</pre></details>"
        else:
            # For other integrity errors
            return False, f"Database integrity error: {str(ie)}"
    except Exception as e:
        logger.error(f"❌ Error type: {type(e).__name__}")
        import traceback
        logger.error(f"❌ Full traceback: {traceback.format_exc()}")
        # db_session.rollback() is handled by the context manager
        
        # Return generic error message
        return False, f"Database error: {str(e)}"

def get_paginated_records(page: int, search_query: str = '') -> Tuple[List, dict]:
    """
    Get paginated POR records with optional search.
    Also attaches all line items to each POR record.
    """
    try:
        current_db = get_current_database()
        db_manager = get_database_manager(current_db)

        with db_manager.session_scope() as db_session:
            query = db_session.query(db_manager.POR).order_by(db_manager.POR.id.desc())
            if search_query:
                search_term = f"%{search_query}%"
                query = query.filter(
                    db_manager.POR.po_number.like(search_term) |
                    db_manager.POR.requestor_name.like(search_term) |
                    db_manager.POR.job_contract_no.like(search_term) |
                    db_manager.POR.op_no.like(search_term) |
                    db_manager.POR.description.like(search_term)
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
                record.line_items = db_session.query(db_manager.LineItem).filter_by(por_id=record.id).all()
            pagination_info = {
                'current_page': page,
                'total_pages': total_pages,
                'total_records': total_records,
                'has_prev': page > 1,
                'has_next': page < total_pages,
                'records_per_page': RECORDS_PER_PAGE
            }
            # db_session.close() is handled by the context manager
            return records, pagination_info
    except Exception as e:
        logger.error(f"Error fetching records: {str(e)}")
        # db_session.close() is handled by the context manager
        return [], {}