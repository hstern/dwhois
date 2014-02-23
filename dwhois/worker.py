import requests
import time

def work_queue(request_url, user=None, password=None,
        sleep_min=1, sleep_max=60):
    error_sleep = sleep_min
    while True:
        try:
            r = requests.get(request_url,
                    auth=(user,password),
                    stream=False,
                    verify=False)
            r.raise_for_status()

            error_sleep = sleep_min
            for domain in r.text.split():
                yield domain
        except (requests.exceptions.HTTPError,
                requests.exceptions.ConnectionError), e:
            print e.message

            time.sleep(error_sleep)
            error_sleep = min(error_sleep*2, sleep_max)
