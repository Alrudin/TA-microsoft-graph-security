# encoding = utf-8

import json
import datetime
import splunk.entity
import urllib
import urlparse

GRAPH_ALERTS_URL = 'https://graph.microsoft.com/v1.0/security/alerts'
ACCESS_TOKEN = 'access_token'
CLIENT_ID = 'client_id'
CLIENT_SECRET = 'client_secret'
TENANT = 'tenant'
LOG_DIRECTORY_NAME = 'logs'
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'


def validate_input(helper, definition):
    interval_in_seconds = int(definition.parameters.get('interval'))
    if interval_in_seconds < 300:
        raise ValueError("field 'Interval' should be at least 300")
    filter_arg = definition.parameters.get('filter')
    if filter_arg is not None and 'lastModifiedDateTime' in filter_arg:
        raise ValueError("'lastModifiedDateTime' is a reserved property and cannot be part of the filter")


def _get_access_token(helper):
    _data = {
        CLIENT_ID: helper.get_arg('app_account')['username'],
        'scope': 'https://graph.microsoft.com/.default',
        CLIENT_SECRET: helper.get_arg('app_account')['password'],
        'grant_type': 'client_credentials'
        }
    _url = 'https://login.microsoftonline.com/' + helper.get_arg('tenant') + '/oauth2/v2.0/token'
    access_token = helper.send_http_request(_url, "POST", payload=urllib.urlencode(_data), timeout=(15.0, 15.0)).json()
    return access_token[ACCESS_TOKEN]
    
    
def _get_app_version(helper):
    app_version = ""
    if 'session_key' in helper.context_meta:
        session_key = helper.context_meta["session_key"]
        entity = splunk.entity.getEntity('/configs/conf-app','launcher', namespace=helper.get_app_name(), sessionKey=session_key, owner='nobody')
        app_version = entity.get('version')
    return app_version
    
    
def _write_events(helper, ew, alerts=None):
    if alerts:
        for alert in alerts:
            event = helper.new_event(
                source=helper.get_input_type(),
                index=helper.get_output_index(),
                sourcetype=helper.get_sourcetype(),
                data=json.dumps(alert))
            ew.write_event(event)


def collect_events(helper, ew):
    access_token = _get_access_token(helper)
    headers = {"Authorization": "Bearer " + access_token,
                "User-Agent": "MicrosoftGraphSecurity-Splunk/" + _get_app_version(helper)}
    interval_in_seconds = int(helper.get_arg('interval'))
    check_point_key = "%s_is_first_time_collecting_events" % helper.get_input_stanza_names()
    is_first_time_collecting_events = 'true'
        # is_first_time_collecting_events = helper.get_check_point(check_point_key)
    if is_first_time_collecting_events != 'false':
        helper.save_check_point(check_point_key, 'false')
        filter_val = ''
    else:
        filter_val = 'lastModifiedDateTime gt ' \
            + (datetime.datetime.utcnow() - datetime.timedelta(seconds=interval_in_seconds)).strftime(TIME_FORMAT) \
            + ' and lastModifiedDateTime lt ' \
            + datetime.datetime.utcnow().strftime(TIME_FORMAT)

    filter_arg = helper.get_arg('filter')
    if filter_arg != '' and filter_arg is not None and filter_arg != 'null':
        if filter_val != '':
            filter_val += ' and '
        filter_val += filter_arg
    params = {'$filter': filter_val}

    response = helper.send_http_request(GRAPH_ALERTS_URL, "GET", headers=headers, parameters=params, timeout=(15.0, 15.0)).json()
    
    #helper.log_debug("GET Response: " + json.dumps(response, indent=4))
    alerts = []
    if "error" in response:
        helper.log_info("Make sure your app with id {} has the Microsoft Graph \"SecurityEvents.Read.All\" permission and your tenant admin has given your application admin consent".format(helper.get_arg('app_account')['username']))
        raise ValueError("Error occured : " + json.dumps(response, indent=4))
    if isinstance(response['value'], dict):
            alerts = alerts + [response['value']]
    elif isinstance(response['value'], list):
        alerts = alerts + response['value']
    remove_nulls(alerts)
    _write_events(helper, ew, alerts=alerts)

    while ("@odata.nextLink" in response) and (is_https(response["@odata.nextLink"])):
        response = helper.send_http_request(response["@odata.nextLink"],"GET", headers=headers, timeout=(15.0, 15.0)).json()
        alerts = []
        if isinstance(response['value'], dict):
            alerts = alerts + [response['value']]
        elif isinstance(response['value'], list):
            alerts = alerts + response['value']
        remove_nulls(alerts)
        _write_events(helper, ew, alerts=alerts)
        

def is_https(url):
    t = urlparse.urlparse(url)
    if t.scheme == "https":
        return True
    else:
        return False


def remove_nulls (d):
    """ Funtion to remove all null or empty values from the JSON response."""
    if isinstance(d, dict):
        for  k, v in list(d.items()):
            if v is None or v == '' or v == []:
                del d[k]
            else:
                remove_nulls(v)
    if isinstance(d, list):
        for v in d:
            remove_nulls(v)
    return d
