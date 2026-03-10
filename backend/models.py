from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from .database import Base
from . import security
import datetime


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name_encrypted = Column(String, nullable=False)
    pan_encrypted = Column(String, nullable=False)
    salary_encrypted = Column(String, nullable=False)

    policies = relationship("LoanPolicy", back_populates="user")

    @property
    def name(self) -> str:
        return security.decrypt_pii(self.name_encrypted)

    @name.setter
    def name(self, plain: str):
        self.name_encrypted = security.encrypt_pii(plain)

    @property
    def pan(self) -> str:
        return security.decrypt_pii(self.pan_encrypted)

    @pan.setter
    def pan(self, plain: str):
        self.pan_encrypted = security.encrypt_pii(plain)

    @property
    def salary(self) -> float:
        return float(security.decrypt_pii(self.salary_encrypted))

    @salary.setter
    def salary(self, plain):
        # accept numeric or string
        self.salary_encrypted = security.encrypt_pii(str(plain))


class LoanPolicy(Base):
    __tablename__ = "loan_policies"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    status = Column(String, nullable=False)
    tier = Column(String, nullable=False)
    applied_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User", back_populates="policies")


class Ledger(Base):
    __tablename__ = "ledger"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    transaction_type = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    previous_hash = Column(String, nullable=True)
    current_hash = Column(String, nullable=False)

    user = relationship("User")
