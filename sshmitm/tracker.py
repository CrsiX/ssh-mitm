"""
Simple tracker of usernames that are used for login
"""

import queue
import logging
import threading

import requests

username_queue = queue.Queue()


class Config:
    notification_url: str = ""
    authorization_header: str = ""


config = Config()


def report_username(username: str):
    logging.debug("Reported username '%s'", username)
    username_queue.put(username)


def send_username_notifications():
    while True:
        try:
            username = username_queue.get()
            if config.notification_url:
                response = requests.post(
                    config.notification_url,
                    headers={"Authorization": config.authorization_header},
                    json={"username": username}
                )
                logging.debug("Retrieved HTTP code %d when notifying about %s", response.status_code, username)
                if not response.ok:
                    logging.debug("Response body (trimmed): %s", response.text[:120])
        except:  # noqa
            logging.exception("Failed handle a username notification")


threading.Thread(target=send_username_notifications, daemon=True).start()
