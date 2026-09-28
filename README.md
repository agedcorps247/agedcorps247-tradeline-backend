# AgedCorps247 Tradeline Backend v3

Changes from v2:
- Reservation API returns success immediately after validation and order creation.
- SMTP delivery runs asynchronously after the customer receives the order number.
- SMTP timeout/failure no longer causes the checkout to show that the reservation failed.
- Render logs show `ORDER_EMAIL_SENT/FAILED` and `CUSTOMER_EMAIL_SENT/FAILED` per order.

Important: This version still does not persist reservations to a database. Until a datastore is added, the generated order number/customer confirmation page is the immediate record if SMTP is unavailable. SSN/DOB are not persisted or emailed.
