import sys
sys.path.append('.')
from database_managers import get_database_manager
from batch_number_manager import get_batch_manager

try:
    fdec_db_manager = get_database_manager('fdec')
    fdec_session = fdec_db_manager.get_session()

    # Get FDEC BatchCounter value
    fdec_batch_manager = get_batch_manager('fdec')
    current_fdec_po_counter = fdec_batch_manager.get_current_batch_number()
    print(f"Current FDEC Batch Counter: {current_fdec_po_counter}")

    # Get highest PO number from FDEC POR table
    FDEC_POR = fdec_db_manager.POR
    highest_fdec_por = fdec_session.query(FDEC_POR).order_by(FDEC_POR.po_number.desc()).first()
    highest_fdec_po_used = highest_fdec_por.po_number if highest_fdec_por else 0
    print(f"Highest FDEC PO number in POR table: {highest_fdec_po_used}")

    fdec_session.close()

except Exception as e:
    print(f"Error inspecting FDEC database: {e}")
