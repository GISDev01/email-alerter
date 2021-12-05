import requests
import os
import feedparser

import sys
import logging
from logging import handlers

import yaml

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


def get_feed_data():
    logger.info("Getting feed data from: {}".format(config["feed_url"]))
    feed_url_request_response = requests.get(config['feed_url'])
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
    import smtplib
    from email.message import EmailMessage

    msg = EmailMessage()

    email_username = config["email_username"]
    email_pwd = config["email_pwd"]
    email_recipient = config["email_recipient"]

    try:
        msg['From'] = email_username
        msg['Subject'] = 'Links'
        msg['To'] = email_recipient
        shows_body = ['; '.join(show) for show in shows]

        msg.set_content('plain text email')
        msg.add_alternative(f"""\
            <!DOCTYPE html>
            <html>
               <body>
                  <p>{'<br>'.join(shows_body)}</p>
               </body>
            </html>
           """, subtype='html')

        with smtplib.SMTP_SSL(host=config['email_server'], port=465) as smtp:
            smtp.ehlo()
            smtp.login(email_username, email_pwd)
            smtp.send_message(msg)


    except:
        logger.exception("Unable to connect to email server.")


def create_email_body(shows):
    text = ""
    for show in shows:
        for val in show:
            text += str(val) + "; "
        text += " <br><br>"

    return text.replace("[", "").replace("]", "")


if __name__ == "__main__":
    feed = get_feed_data()
    shows_to_email = parse_feed_for_shows(feed)
    send_email_with_shows(shows_to_email)
