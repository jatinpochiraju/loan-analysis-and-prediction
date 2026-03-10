# Module for claim management

class ClaimCenter:
    def __init__(self):
        self.claims = []

    def file_claim(self, user, details):
        claim = {"user": user, "details": details, "status": "filed"}
        self.claims.append(claim)
        return claim
