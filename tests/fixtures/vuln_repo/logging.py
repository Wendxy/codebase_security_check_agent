import logging

def log_checkout(email: str, card_number: str):
    logging.info("checkout email=%s card=%s", email, card_number)
