"""
Database models for POR (Purchase Order Request) system.
Defines the POR table structure and database configuration.
"""

import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, Index, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.pool import StaticPool
from config import COMPANIES

# Database configuration - will be set dynamically based on company
DATABASE_URL = os.environ.get('DATABASE_URL', "sqlite:///a&p_por.db")

print("Using database at:", DATABASE_URL)

# Handle Railway's PostgreSQL URL format
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Create engine with optimized settings
engine = create_engine(
    DATABASE_URL,
    future=True,
    poolclass=StaticPool,  # Better for single-threaded apps
    pool_pre_ping=True,    # Verify connections before use
    echo=False             # Set to True for SQL debugging
)

# Create declarative base
Base = declarative_base()




class BatchCounter(Base):
    __tablename__ = "batch_counter"
    id = Column(Integer, primary_key=True)
    value = Column(Integer, nullable=False)

def get_or_create_batch_counter(session):
    counter = session.query(BatchCounter).first()
    if not counter:
        counter = BatchCounter(value=COMPANIES['a&p']['batch_start'])
        session.add(counter)
        session.commit()
    return counter


class POR(Base):
    """
    Purchase Order Request model.
    
    Stores processed POR data extracted from Excel files.
    """
    __tablename__ = "por"
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Core POR data
    po_number = Column(Integer, unique=True, nullable=False, index=True)
    requestor_name = Column(String(255), nullable=False, index=True)
    date_order_raised = Column(String(50), nullable=False)
    date_required_by = Column(String(50))
    ship_project_name = Column(String(255), index=True)
    supplier = Column(String(255), index=True)
    filename = Column(String(255), nullable=False)
    company = Column(String(10), nullable=True, default='a&p')  # Company field for database compatibility
    
    # Line item details
    job_contract_no = Column(String(100), index=True)
    op_no = Column(String(50), index=True)
    description = Column(Text)
    quantity = Column(Integer)
    price_each = Column(Float)
    line_total = Column(Float)
    order_total = Column(Float)
    
    # Additional fields from parsing map
    specification_standards = Column(Text)
    supplier_contact_name = Column(String(255))
    supplier_contact_email = Column(String(255))
    quote_ref = Column(String(255))
    quote_date = Column(String(50))
    show_price = Column(String(10))  # Y/N field for showing prices
    
    # Metadata
    data_summary = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Timeline and Status fields
    current_stage = Column(String(20), default='received', nullable=False)  # 'received', 'sent', 'filed'
    status_color = Column(String(20), default='normal', nullable=False)  # 'normal', 'orange', 'red', 'green'
    order_type = Column(String(20), default='new', nullable=False)  # 'new', 'revised', 'cancelled'
    content_type = Column(String(20), default='supply', nullable=False)  # 'work_iwo', 'supply_and_fit', 'supply'
    received_comments = Column(Text)  # Comments for Received stage
    sent_comments = Column(Text)  # Comments for Sent stage
    filed_comments = Column(Text)  # Comments for Filed stage
    amazon_comment = Column(Text)  # Special comment for Amazon orders
    work_date_comment = Column(Text)  # Special comment for same date orders
    stage_updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    change_history = Column(Text)  # JSON string of change history (max 100 changes)
    current_change_index = Column(Integer, default=-1)  # Current position in change history
    
    # Relationship to attached files
    attached_files = relationship("PORFile", back_populates="por", cascade="all, delete-orphan")
    
    # Composite index for common searches
    __table_args__ = (
        Index('idx_po_requestor', 'po_number', 'requestor_name'),
        Index('idx_job_op', 'job_contract_no', 'op_no'),
    )
    
    # Add relationship to POR
    line_items = relationship("LineItem", back_populates="por", cascade="all, delete-orphan")
    
    def __repr__(self):
        """String representation of POR record."""
        return f"<POR(po_number={self.po_number}, requestor='{self.requestor_name}')>"
    
    def to_dict(self):
        """Convert POR record to dictionary."""
        return {
            'id': self.id,
            'po_number': self.po_number,
            'requestor_name': self.requestor_name,
            'date_order_raised': self.date_order_raised,
            'filename': self.filename,
            'job_contract_no': self.job_contract_no,
            'op_no': self.op_no,
            'description': self.description,
            'quantity': self.quantity,
            'price_each': self.price_each,
            'line_total': self.line_total,
            'order_total': self.order_total,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class PORFile(Base):
    """
    POR File attachment model.
    
    Stores files attached to POR records for auditing purposes.
    """
    __tablename__ = "por_files"
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Foreign key to POR
    por_id = Column(Integer, ForeignKey('por.id'), nullable=False, index=True)
    
    # File information
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)
    file_type = Column(String(50), nullable=False)  # 'original', 'quote', 'other'
    file_size = Column(Integer)  # Size in bytes
    mime_type = Column(String(100))
    
    # Metadata
    uploaded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    description = Column(String(500))  # Optional description
    
    # Relationship to POR
    por = relationship("POR", back_populates="attached_files")
    
    def __repr__(self):
        """String representation of PORFile record."""
        return f"<PORFile(filename='{self.original_filename}', type='{self.file_type}')>"
    
    def to_dict(self):
        """Convert PORFile record to dictionary."""
        return {
            'id': self.id,
            'por_id': self.por_id,
            'original_filename': self.original_filename,
            'stored_filename': self.stored_filename,
            'file_type': self.file_type,
            'file_size': self.file_size,
            'mime_type': self.mime_type,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
            'description': self.description
        }


class LineItem(Base):
    """
    Line Item model for POR.
    Stores individual line items for each Purchase Order Request.
    """
    __tablename__ = "line_items"

    id = Column(Integer, primary_key=True, autoincrement=True)
    por_id = Column(Integer, ForeignKey('por.id'), nullable=False, index=True)
    job_contract_no = Column(String(100), index=True)
    op_no = Column(String(50), index=True)
    description = Column(Text)
    specifications = Column(Text)  # New field for specifications
    quantity = Column(Integer)
    price_each = Column(Float)
    line_total = Column(Float)

    por = relationship("POR", back_populates="line_items")


def init_database():
    """Initialize database tables."""
    try:
        Base.metadata.create_all(engine)
        print("✅ Database tables created successfully")
    except Exception as e:
        print(f"❌ Error creating database tables: {e}")
        raise


def get_session():
    """Get a new database session."""
    Session = sessionmaker(bind=engine)
    return Session()

# Initialize database on import
if __name__ == '__main__':
    init_database()