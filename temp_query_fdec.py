import sys
sys.path.append('.') # Add current directory to path to import modules

from database_managers import get_database_manager
from batch_number_manager import get_batch_manager

try:
    company_name = 'fdec'
    db_manager = get_database_manager(company_name)
    session = db_manager.get_session()

    # Get BatchCounter value
    batch_counter_model = db_manager.BatchCounter
    counter = session.query(batch_counter_model).filter_by(company=company_name).first()
    current_batch_value = counter.value if counter else "Not Found"

    # Get highest PO number from POR table
    por_model = db_manager.POR
    highest_por = session.query(por_model).order_by(por_model.po_number.desc()).first()
    highest_po_used = highest_por.po_number if highest_por else 0

    print(f"FDEC Current Batch Counter Value: {current_batch_value}")
    print(f"FDEC Highest PO Used: {highest_po_used}")

except Exception as e:
    print(f"Error querying database: {e}")
finally:
    if 'session' in locals() and session:
        session.close()