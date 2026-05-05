# LoanShield KYC OCR Sample Documents

Use these files on `/user/kyc-onboarding` with the matching document type dropdown.

For best OCR verification results, fill the KYC onboarding profile with these values first:

- Full Name: Arjun Mehta
- PAN Number: ABCDE1234F
- Company Name: FinEdge Analytics Pvt Ltd
- Designation: Software Engineer
- Years of Experience: 3
- Monthly Salary: 85000
- Requested Loan: 600000
- Existing EMI: 12000

Upload mapping:

| Dropdown Document Type | File |
|---|---|
| PAN Card | `01_pan_card_arjun_mehta.pdf` |
| Salary Slip 1 | `02_salary_slip_1_april_2026.pdf` |
| Salary Slip 2 | `03_salary_slip_2_march_2026.pdf` |
| Salary Slip 3 | `04_salary_slip_3_february_2026.pdf` |
| Joining Letter | `05_joining_letter_finedge.pdf` |
| Bank Statement (6 months) | `06_bank_statement_6_months.pdf` |

PDF versions are ready for upload. The `.txt` files are kept as editable source fixtures. The OCR simulation has also been updated to extract text from uploaded PDFs using `pdftotext` before applying the existing KYC verification parser.
