# Module for billing management

class BillingCenter:
    def __init__(self):
        self.records = []

    def add_charge(self, user, amount):
        record = {"user": user, "amount": amount}
        self.records.append(record)
        return record
