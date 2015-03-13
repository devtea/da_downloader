#!/bin/python3
import requests
import time
import os
import sys
import re
from html.parser import HTMLParser

import config
import logger

_CONFIGFILE = 'config.yaml'
_WAIT = 0.25  # global rait limiting value, don't set to 0
_EXT = re.compile('^http.*/download/[0-9]+/[^\.]+(\.[a-zA-Z]{2,4})\?token=.*$')

log = logger.getLogger()
log.info('Initializing project')


class ImageParser(HTMLParser):
    def get_img(self):
        try:
            return self.img
        except:
            return None


class DAParser(ImageParser):
    def handle_starttag(self, tag, attrs):
        # Easiest way to grab an image from deviant art is to parse the page
        # and pull out the (hopefully) only link ('a' tag) with a class of
        # 'dev-page-download'
        try:
            if tag == 'a' and attrs:
                # Attrs are a list of tuples, (name, value)
                d = {}
                for attr in attrs:
                    d[attr[0]] = attr[1]
                if d and 'class' in d and 'dev-page-download' in d['class'].split():
                    log.debug(d)
                    self.img = d['href']
        except:
            log.error('Unhandled exception in DA Parser', exc_info=True)
            raise


def download_image(path, url, cookies=None, referrer=None):
    '''Wrapper around requests to attempt downloading a file at a specified URL'''
    try:
        log.debug("Beginning download.")
        downloaded_image = requests.get(url, cookies=cookies, headers={'referrer': referrer}, stream=True)
        log.debug("Finished download.")
        if downloaded_image.ok:
            with open(path, 'wb') as f:
                for block in downloaded_image.iter_content(1024):
                    if not block:
                        break
                    f.write(block)
            return path
        else:
            return False
    except:
        log.error('Unhandled exception in downloader', exc_info=True)
        return None


def da_api(conf, method, endpoint, payload):
    global _WAIT
    remaining_retries = 10
    reauthed = False
    try:
        while remaining_retries:
            time.sleep(conf['wait'])
            if method == 'get':
                request = requests.get(endpoint, params=payload)
            elif method == 'post':
                request = requests.post(endpoint, data=payload)
            if request.status_code == 200:
                if conf['wait'] > 0.25:
                    conf['wait'] /= 2  # Ratched down our wait time since we succeeded
                    log.debug("Reduced wait time to %s", conf['wait'])
                return request
            elif request.status_code == 401:  # Invalid token, need to refresh
                # reauth with the api
                if not reauthed:  # Only reauth once per loop to prevent infinite reauthing
                    remaining_retries += 1
                conf['access_token'] = auth(conf['client_id'], conf['client_secret'])
                reauthed = True
            elif request.status_code == 429:  # API rate limiting
                log.warning("API ratelimiting encountered.")
                log.debug("Request status code: %s", request.status_code)
                log.debug("Request contents: %s", request.text)
                conf['wait'] *= 4
                log.debug("increased wait time to %s", conf['wait'])
            else:
                # lolidunno
                log.warning("Unknown response from server.")
                log.debug("Request status code: %s", request.status_code)
                log.debug("Request contents: %s", request.text)
                conf['wait'] *= 10  # Don't know what went wrong, so lets wait a long time to see if it fixes itself
                log.debug("increased wait time to %s", conf['wait'])
            remaining_retries -= 1
            log.debug("%s retries remaining", remaining_retries)
    except:
        log.error('Unhandled exception in api wrapper', exc_info=True)
        return None


def auth(id, secret):
    try:
        oid_request = requests.post(
            'https://www.deviantart.com/oauth2/token',
            data={'grant_type': 'client_credentials', 'client_id': id, 'client_secret': secret}
        )

        '''
        Successful requests look like
        oid_request.json()

        {'access_token': '1a2b3a21a3b21ab2132b15a46b8a7b9513a2b16a8b79a79842ab1654957a98',
        'expires_in': 3600,
        'status': 'success',
        'token_type': 'Bearer'}
        '''
        if oid_request and oid_request.ok and 'status' in oid_request.json() and oid_request.json()['status'] == 'success':
            access_token = oid_request.json()['access_token']
            log.debug("Got access token: %s", access_token)
        else:
            log.critical("Unable to get oauth token from API")
            log.debug("Request okay: %s", oid_request.ok)
            log.debug("Request status code: %s", oid_request.status_code)
            log.debug("Request encoding: %s", oid_request.encoding)
            log.debug("Request contents: %s", oid_request.text)
            log.debug("Request json: %s", oid_request.json())
            oid_request.raise_for_status
        return access_token
    except:
        log.error('Unhandled exception in api wrapper', exc_info=True)
        raise


def api_paged(conf, method, endpoint, payload, limit=None):
    '''Wrapper for da_api that pulls all paged results out'''
    items = []
    offset = 0
    has_more = True

    if limit:
        payload['limit'] = limit
    elif 'limit' not in payload:
        payload['limit'] = 10

    while has_more:
        payload['offset'] = offset
        page = da_api(conf, method, endpoint, payload)
        if not page:
            log.critical("Unable to get page from API at %s. Deviant art may be unavailable.", endpoint)
            sys.exit(1)
        items.extend(page.json()['results'])
        has_more = 'has_more' in page.json() and page.json()['has_more']
        if has_more:
            log.debug('On page offset %s and api reports more. Next offset %s', offset, page.json()['next_offset'])
            offset = page.json()['next_offset']
    return items


def main(args):
    conf = config.getConfig(_CONFIGFILE)
    if not conf:
        log.critical('Invalid config.')
        sys.exit(1)

    if 'log level' in conf and conf['log level'].upper() in [
            'CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
        log.setLevel(conf['log level'].upper())
        log.info("Set logging level to %s", conf['log level'].upper())
    elif 'log level' in conf:
        log.warning('Invalid log level specified in config. Level must be one of [critical, error, warning, info, debug].')

    # Set some internal values
    conf['wait'] = _WAIT
    conf['access_token'] = auth(conf['client_id'], conf['client_secret'])

    collections = api_paged(
        conf,
        'get',
        'https://www.deviantart.com/api/v1/oauth2/collections/folders',
        {'username': conf['user'], 'access_token': conf['access_token']},
        50
    )
    log.debug('Found %i collections for user %s.', len(collections), conf['user'])

    folder_id = None
    try:
        folder_id = [f['folderid'] for f in collections if f['name'].lower() == conf['category'].lower()][0]
    except IndexError:
        log.critical("Collection %s Not found for user %s", conf['category'], conf['user'])
        sys.exit(1)
    log.debug('Found folder id %s for folder %s for user %s', folder_id, conf['category'], conf['user'])

    deviations = api_paged(
        conf,
        'get',
        'https://www.deviantart.com/api/v1/oauth2/collections/%s' % folder_id,
        {'username': conf['user'], 'mature_content': 'true', 'access_token': conf['access_token']},
        24
    )
    deviation_count = len(deviations)
    log.info('Got %i deviations to fetch.', deviation_count)

    downloaded = os.listdir(conf['output_path'])

    i = -1  # Setup for completion percentage
    for deviation in deviations:
        try:
            i += 1
            log.info('Working on image %i of %i - %s%s complete.' % (i, deviation_count, str((i/deviation_count)*100)[:4], r'%'))

            url = deviation['url']
            log.debug("")
            log.debug("Working with deviation %s", url)

            if deviation['is_deleted']:
                log.info("Deviation is deleted, skipping.")
                continue
            if deviation['is_mature']:
                log.debug("Deviation is marked as mature.")

            # TODO Need to check type returned when downloading actual image.
            ext = os.path.splitext(deviation['content']['src'])[-1]
            # Black magic to pull trailing unique identifier, or just filename
            # sans extension or path
            unq = os.path.splitext(os.path.split(deviation['content']['src'])[-1])[0].split('-')[-1]
            # Generate file name
            filename = '%s_%s-%s%s' % (deviation['author']['username'], deviation['title'], unq, ext)
            # Sanitize path of unsafe characters
            path = ''.join([c for c in filename if c.isalpha() or c.isdigit() or c in '-_.() ']).strip()
            log.debug("Looking for file %s", path)
            if path in downloaded:
                log.info('Deviation exists in output path, skipping.')
                continue
            # Generate full path
            path = os.path.join(conf['output_path'], path)
            log.debug("Output path will be: %s", path)

            unsuccessful = True
            if deviation['is_downloadable']:
                log.debug("Deviation is flagged as downloadable")
                log.debug("Scraping %s for full image.", url)
                parser = DAParser(convert_charrefs=True)
                d_page = requests.get(url)
                parser.feed(d_page.text)
                img = parser.get_img()
                del parser

                if img:
                    log.debug("Found image url: %s", img)

                    # get real extension here and rebuild file name
                    ext = _EXT.findall(img)[0]
                    filename = '%s_%s-%s%s' % (deviation['author']['username'], deviation['title'], unq, ext)
                    path = ''.join([c for c in filename if c.isalpha() or c.isdigit() or c in '-_.() ']).strip()
                    log.debug("Looking for full file %s", path)
                    if path in downloaded:
                        log.info('Deviation exists in output path, skipping.')
                        continue
                    path = os.path.join(conf['output_path'], path)

                    if download_image(path=path, url=img, cookies=d_page.cookies, referrer=url):
                        unsuccessful = False
                    unsuccessful = False
                else:
                    log.warning("No image found when scraping page %s", url)

            if unsuccessful:
                # Get provided image
                # TODO Handle images that you must be logged in to see.
                log.debug('Falling back to content from API')
                url = deviation['content']['src']
                log.debug("Using image url: %s", url)
                download_image(path=path, url=url)

            time.sleep(1)  # Be nice to Deviant Art :)
        except:
            log.error("Unhandled exception when downloading deviations.", exc_info=True)
    log.info('Finished')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        log.warning('Caught keyboard interrupt. Closing.')
        sys.exit(1)
