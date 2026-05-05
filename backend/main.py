from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from . import models, security, logic
from .database import engine, get_db
from pydantic import BaseModel
import datetime

# create tables when module is imported; for production use migrations instead
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="LoanShield API")


class ApplyRequest(BaseModel):
    name: str
    pan: str
    salary: str
    loan_amount: float
    expense: float


class PaymentRequest(BaseModel):
    user_id: int
    amount: float
    transaction_type: str


@app.post("/api/apply")
def apply(req: ApplyRequest, db: Session = Depends(get_db)):
    def _decrypt_or_plaintext(value):
        try:
            return security.decrypt_pii(value)
        except Exception:
            return value

    try:
        name = _decrypt_or_plaintext(req.name)
        pan = _decrypt_or_plaintext(req.pan)
        salary = float(_decrypt_or_plaintext(req.salary))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid payload") from exc

    decision = logic.predict_loan_status(salary, req.expense, req.loan_amount)
    user = models.User()
    user.name = name
    user.pan = pan
    user.salary = salary
    db.add(user)
    db.commit()
    db.refresh(user)

    policy = models.LoanPolicy(
        user_id=user.id,
        amount=req.loan_amount,
        status=decision["status"],
        tier=decision["tier"],
    )
    db.add(policy)
    db.commit()

    # asynchronously notify external system (fire-and-forget)
    logic.sync_with_guidewire()

    return {"status": decision["status"], "tier": decision["tier"]}


@app.post("/api/payment")
def payment(req: PaymentRequest, db: Session = Depends(get_db)):
    last = db.query(models.Ledger).order_by(models.Ledger.id.desc()).first()
    prev_hash = last.current_hash if last else None
    timestamp = datetime.datetime.utcnow()
    current_hash = security.generate_block_hash(prev_hash, req.user_id, req.amount, timestamp)

    ledger = models.Ledger(
        user_id=req.user_id,
        amount=req.amount,
        transaction_type=req.transaction_type,
        previous_hash=prev_hash,
        current_hash=current_hash,
        timestamp=timestamp,
    )
    db.add(ledger)
    db.commit()
    db.refresh(ledger)

    return {"transaction_id": ledger.id, "hash": current_hash}
