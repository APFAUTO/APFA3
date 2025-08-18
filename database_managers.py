"""
Independent Database Managers for A&P and FDEC Companies.
Each company has completely isolated database logic with no shared state.
"""

import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, Index, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.pool import StaticPool

class DatabaseManager:
    """Base database manager with isolated database logic."""
    
    def __init__(self, company_name, db_filename, batch_start):
        self.company_name = company_name
        self.db_filename = db_filename
        self.batch_start = batch_start
        self.database_url = f"sqlite:///{db_filename}"
        
        # Create isolated engine for this company
        self.engine = create_engine(
            self.database_url,
            future=True,
            poolclass=StaticPool,
            pool_pre_ping=True,
            echo=False
        )
        
        # Create isolated declarative base
        self.Base = declarative_base()
        
        # Define models for this company
        self._define_models()
        
        # Create session factory
        self.SessionLocal = sessionmaker(bind=self.engine)
        
        print(f"Initialized {company_name} database manager: {db_filename}")
    
    def _define_models(self):
        """Define database models for this company."""
        Base = self.Base
        
        class POR(Base):
            """Purchase Order Request model for this company."""
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
            company = Column(String(10), nullable=True, default=self.company_name)
            
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
            show_price = Column(String(10))
            
            # Metadata
            data_summary = Column(Text)
            created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
            
            # Timeline and Status fields
            current_stage = Column(String(20), default='received', nullable=False)
            status_color = Column(String(20), default='normal', nullable=False)
            order_type = Column(String(20), default='new', nullable=False)
            content_type = Column(String(20), default='supply', nullable=False)
            received_comments = Column(Text)
            sent_comments = Column(Text)
            filed_comments = Column(Text)
            amazon_comment = Column(Text)
            work_date_comment = Column(Text)
            fdec_warning = Column(Text)  # Warning message for FDEC job numbers
            stage_updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
            change_history = Column(Text)
            current_change_index = Column(Integer, default=-1)
            
            # Relationships
            attached_files = relationship("PORFile", back_populates="por", cascade="all, delete-orphan")
            line_items = relationship("LineItem", back_populates="por", cascade="all, delete-orphan")
            
            # Composite indexes
            __table_args__ = (
                Index('idx_po_requestor', 'po_number', 'requestor_name'),
                Index('idx_job_op', 'job_contract_no', 'op_no'),
            )
            
            def __repr__(self):
                return f"<POR(po_number={self.po_number}, requestor='{self.requestor_name}')>"
        
        class PORFile(Base):
            """POR File attachment model for this company."""
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
            
            por = relationship("POR", back_populates="attached_files")
            
            def __repr__(self):
                return f"<PORFile(filename='{self.original_filename}', type='{self.file_type}')>"
        
        class LineItem(Base):
            """Line Item model for this company."""
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
            
            por = relationship("POR", back_populates="line_items")
        
        class BatchCounter(Base):
            """Batch counter for this company."""
            __tablename__ = "batch_counter"
            
            id = Column(Integer, primary_key=True)
            company = Column(String(50), unique=True, nullable=False) # Added company column
            value = Column(Integer, nullable=False)
        
        # Store models as class attributes
        self.POR = POR
        self.PORFile = PORFile
        self.LineItem = LineItem
        self.BatchCounter = BatchCounter
    
    def init_database(self):
        """Initialize database tables for this company."""
        try:
            self.Base.metadata.create_all(self.engine)
            print(f"{self.company_name} database tables created successfully")
        except Exception as e:
            print(f"Error creating {self.company_name} database tables: {e}")
            raise
    
    def get_session(self):
        """Get a new database session for this company."""
        return self.SessionLocal()
    
    def get_or_create_batch_counter(self, session):
        """Get or create batch counter for this company."""
        # Filter by company to get the correct counter
        counter = session.query(self.BatchCounter).filter_by(company=self.company_name).first()
        if not counter:
            # Create with company name
            counter = self.BatchCounter(company=self.company_name, value=self.batch_start)
            session.add(counter)
            session.commit()
        return counter


# Create independent database managers for each company
class APDatabaseManager(DatabaseManager):
    """A&P Company Database Manager - Completely Independent."""
    
    def __init__(self):
        super().__init__('a&p', 'a&p_por.db', 5000)


class FDECDatabaseManager(DatabaseManager):
    """FDEC Company Database Manager - Completely Independent."""
    
    def __init__(self):
        super().__init__('fdec', 'fdec_por.db', 6000)


# Global instances - each completely isolated
ap_db = APDatabaseManager()
fdec_db = FDECDatabaseManager()

# Initialize both databases
ap_db.init_database()
fdec_db.init_database()

def get_database_manager(company_name):
    """Get the appropriate database manager for a company."""
    if company_name == 'a&p':
        return ap_db
    elif company_name == 'fdec':
        return fdec_db
    else:
        raise ValueError(f"Unknown company: {company_name}")