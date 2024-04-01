"""
Tracker of username & password combinations that
will also set up accounts for unsuccessful logins
via shell or HTTP provisioning methods
"""

import time
import queue
import logging
import threading
import subprocess
from typing import Optional

import requests
from paramiko.pkey import PKey

from sshmitm.clients.ssh import AuthenticationMethod as _AuthM


tracking_queue = queue.Queue()


class Config:
    notification_url: str = ""
    notification_authorization: str = ""
    provision_cmd: str = ""
    provision_url: str = ""
    provision_authorization: str = ""
    identifier: str = ""


config = Config()


def send_tracking_notifications():
    while True:
        data = None
        try:
            data = tracking_queue.get()
            if config.notification_url:
                response = requests.post(
                    config.notification_url,
                    headers={"Authorization": config.notification_authorization},
                    json=data
                )
                user = data.get("username", "N/A")
                logging.debug("Retrieved HTTP code %d when notifying about %s", response.status_code, user)
                if not response.ok:
                    logging.debug("Response body (trimmed): %s", response.text[:120])
        except Exception as exc:  # noqa
            logging.warning("Failed to handle a connection notification: %s: %s", type(exc).__name__, exc)
            logging.debug("Data associated with the failed notification: %s", data)


def provision(user: str, method: _AuthM, password: Optional[str] = None, _: Optional[PKey] = None) -> bool:
    """
    Request the provision of a new user account with the given credentials
    """

    if method != _AuthM.PASSWORD:
        return False
    if config.provision_cmd:
        logging.debug("Requesting shell provisioning for user %s", user)
        cmd = config.provision_cmd
        try:
            cmd = config.provision_cmd % user
        except TypeError:
            pass
        try:
            cmd = config.provision_cmd % (user, password)
        except TypeError:
            pass
        start = time.time()
        code, output = subprocess.getstatusoutput(cmd)
        end = time.time()
        logging.debug(
            "Received code %d with output of %d bytes (trimmed) in %.3f sec: %s",
            code,
            len(output),
            end - start,
            output[:30]
        )
        return code == 0

    data = {
        "username": user,
        "password": password,
        "identifier": config.identifier
    }
    try:
        logging.debug("Requesting HTTP provisioning for user %s", user)
        response = requests.post(
            config.provision_url,
            headers={"Authorization": config.provision_authorization},
            json=data
        )
        logging.debug("Retrieved HTTP code %d when provisioning %s", response.status_code, user)
        if not response.ok:
            logging.debug("Response body (trimmed): %s", response.text[:120])
    except Exception as exc:
        logging.warning("Failed to handle a provisioning request: %s: %s", type(exc).__name__, exc)
        logging.debug("Data associated with the failed provisioning request: %s", data)
        return False
    return True


def track(
        user: str,
        method: _AuthM,
        password: Optional[str] = None,
        public_key: Optional[PKey] = None,
        remote: tuple = ()
):
    """
    Track requested usernames, passwords and public keys for remote connections
    """

    tracking_queue.put({
        "username": user,
        "password": password,
        "method": method.value,
        "public_key": public_key and public_key.get_base64(),
        "public_key_fingerprint": public_key and public_key.get_fingerprint().hex().lower(),
        "remote_ip": remote and remote[0],
        "remote_port": remote and remote[1],
        "remote_extra": remote and len(remote) > 2 and "|".join(map(str, remote[2:])) or None,
        "timestamp": time.time(),
        "identifier": config.identifier
    })


threading.Thread(target=send_tracking_notifications, daemon=True).start()
