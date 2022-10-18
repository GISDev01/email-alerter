import json

import requests
import os
import feedparser

import sys
import logging
from logging import handlers

import yaml

import base64
import logging
import mimetypes
import os
import os.path
import pickle
from email.mime.text import MIMEText
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient import errors
from googleapiclient.discovery import build

if not os.path.isfile(os.path.join('config', 'config.yml')):
    print('config.yml was not found. You probably need to rename the config.yml.template to config.yml ' +
          'and insert your credentials in this config file')
    sys.exit()


def get_logger():
    logs_dir_name = 'log'
    if not os.path.exists(logs_dir_name):
        os.makedirs(logs_dir_name)

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    LOG_FORMAT = logging.Formatter('%(asctime)-15s %(levelname)s: %(message)s')

    stdout_logger = logging.StreamHandler(sys.stdout)
    stdout_logger.setFormatter(LOG_FORMAT)
    logger.addHandler(stdout_logger)

    file_logger = handlers.RotatingFileHandler(os.path.join(logs_dir_name, 'email-alerter.log'),
                                               maxBytes=(1048576 * 5),
                                               backupCount=3)
    file_logger.setFormatter(LOG_FORMAT)
    logger.addHandler(file_logger)
    return logger


def get_config():
    try:
        with open(os.path.join("config", "config.yml"), "r") as yaml_config_file:
            _config = yaml.load(yaml_config_file, Loader=yaml.SafeLoader)
        return _config
    except:
        logger.exception('config.yml file cannot be found or read. '
                         'You might need to fill in the the config.yml.template and then rename it to config.yml')


logger = get_logger()
config = get_config()


def get_service():
    """Gets an authorized Gmail API service instance.

    Returns:
        An authorized Gmail API service instance..
    """

    # If modifying these scopes, delete the file token.pickle.
    SCOPES = [
        'https://www.googleapis.com/auth/gmail.send',
    ]

    creds = None
    # The file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'creds.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)
    return service


def send_message(service, sender, message):
    """Send an email message.

    Args:
      service: Authorized Gmail API service instance.
      user_id: User's email address. The special value "me"
      can be used to indicate the authenticated user.
      message: Message to be sent.

    Returns:
      Sent Message.
    """
    try:
        sent_message = (service.users().messages().send(userId=sender, body=message)
                        .execute())
        logging.info('Message Id: %s', sent_message['id'])
        return sent_message
    except errors.HttpError as error:
        logging.error('An HTTP error occurred: %s', error)


def create_message(sender, to, subject, shows):
    """Create a message for an email.

    Args:
      sender: Email address of the sender.
      to: Email address of the receiver.
      subject: The subject of the email message.
      shows: list of shows

    Returns:
      An object containing a base64url encoded email object.
    """

    message = MIMEText(create_email_body(shows))
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject

    s = message.as_string()
    b = base64.urlsafe_b64encode(s.encode('utf-8'))
    return {'raw': b.decode('utf-8')}


def get_feed_data():
    logger.info("Getting feed data from: {}".format(config["feed_url"]))
    try:
        feed_url_request_response = requests.get(config['feed_url'])
    except Exception as e:
        logger.exception("Unable to get the feed data: ", e)

    try:
        return feedparser.parse(feed_url_request_response.content)
    except Exception as e:
        logger.exception("Unable to parse the feed data: ", e)
        sys.exit(1)


def get_results_from_recordings_page():
    login_url = config["login_url"]

    username = config["playlist_un"]
    pwd = config["playlist_pw"]

    login_payload = {'account_email': username,
                     'account_password': pwd,
                     'submitted_login': 'Sign In'}

    jq_cb = 'jQuery111104801374003609924_1666120535996'
    playlist_payload = {'number_to_display': 20,
                        'sort_by': 6,
                        'recording_type': 1,
                        'page_number': 1,
                        'back_seconds': 8,
                        'skip_seconds': 30,
                        'callback': jq_cb}

    results = []
    with requests.Session() as s:
        r = s.post(login_url, data=login_payload)
        playlist_url = config["playlist_url"]
        playlist = s.post(playlist_url, data=playlist_payload)
        json_resp = playlist.text.replace(jq_cb, '').replace('({', '{').replace(
            ',"page_data":{"current_page":"1","number_of_pages":449}});', '}')
        for result in json.loads(json_resp)["results"][:7]:
            results.append("{}: {}".format(result["title"], result['mp3']))

    return results


def scrape_download_links():
    logger.info("Scraping download links from: {}".format(config["feed_url"]))
    try:
        feed_url_request_response = requests.get(config['feed_url'])
    except Exception as e:
        logger.exception("Unable to get the feed data: ", e)

    try:
        return feedparser.parse(feed_url_request_response.content)
    except Exception as e:
        logger.exception("Unable to parse the feed data: ", e)
        sys.exit(1)


def parse_feed_for_shows(feed):
    shows_to_email = []
    for item in feed.entries:
        show_name = item.title
        published_datetime_local = item.published
        mp3_url = item.links[1]["href"]
        show = [show_name, published_datetime_local, mp3_url]
        logger.debug("Adding show: {}".format(show))
        shows_to_email.append(show)
    return shows_to_email


def send_email_with_shows(shows):
    email_username = config["email_username"]
    email_recipient = config["email_recipient"]

    try:
        service = get_service()
        message = create_message(email_username, email_recipient, "Links", shows)
        send_message(service, email_username, message)

    except Exception as e:
        print(e)
        logging.error(e)
        raise


def create_email_body(shows):
    text = ""
    for show in shows:
        for val in show:
            text += str(val) + ""
        text += " <br>"

    return text.replace("[", "").replace("]", "")


if __name__ == "__main__":
    results = get_results_from_recordings_page()
    # feed = get_feed_data()
    # shows_to_email = parse_feed_for_shows(feed)
    send_email_with_shows(results)
