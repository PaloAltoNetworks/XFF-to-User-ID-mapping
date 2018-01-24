import json
import boto3
import botocore
import time
from boto3 import resource
from boto3 import client
from boto3.dynamodb.conditions import Key, Attr
import urllib2
import ssl
import os
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

client = boto3.client('dynamodb')
dynamodb_resource = resource('dynamodb')
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

table_name = os.environ['dbTable']
# gwMgmtIp = "ec2-52-32-47-26.us-west-2.compute.amazonaws.com"
# apiKey = "LUFRPT1BeDJOUWtoSUp5UjFXWVU5TDBTMk1OanFMeFk9ZXFIMVoxUjltVWx2NUpFUWxoejdxTEYrUFA1S0RZTUV6ejRNUGYwdmYzQT0="
username = "baduser"
useridtimeout = "20"
gwMgmtIp = os.environ['fwMgtIp']
apiKey = "LUFRPT1ETWtoUHduU0R5S0JpY0tvdktnQUFXNWlXR0k9TTlmMkhSMktNM25uM3hscXNnUXV3Zz09"

fw_cmd1 = "https://" + gwMgmtIp + "/api/?type=user-id&action=set&key=" + apiKey + "&cmd=" + "%3Cuid-message%3E%3Cversion%3E1.0%3C/version%3E%3Ctype%3Eupdate%3C/type%3E%3Cpayload%3E%3Clogin%3E"
# uid_payload1 = "%3Centry%20name=%22"+username+"%22%20ip=%22"

uid_payload1 = "%3Centry%20name=%22"
uid_payload2 = "%22%20ip=%22"
uid_payload3 = "%22%20timeout=%22" + useridtimeout + "%22%3E%3C/entry%3E"
fw_cmd2 = "%3C/login%3E%3C/payload%3E%3C/uid-message%3E"


def check_item_count(table_name):
    table = dynamodb_resource.Table(table_name)
    response = table.scan(FilterExpression=Attr('notes').eq('senduid'))
    count = len(response['Items'])
    # count = table.scan()['Count']
    return count


def read_from_db():
    """
    Read from DB and send a list of IP address for which UID mappings need to be sent
    """
    ipaddress_list = []
    table = dynamodb_resource.Table(table_name)
    response = table.scan(FilterExpression=Attr('notes').eq('senduid'))

    for user in response['Items']:
        ipaddress_list.append(user['ipaddress'])

    return ipaddress_list


def update_db(ipaddress_list):
    """
    Update notes attribute to 'uidsent' once the UID mapping is sent
    """
    table = dynamodb_resource.Table(table_name)
    for ip in ipaddress_list:
        table.update_item(Key={'username': ip}, UpdateExpression="set notes = :n",
                          ExpressionAttributeValues={':n': 'uidsent'}, ReturnValues="UPDATED_NEW")

    return


def delete_from_db(ipaddress_list):
    """
    Delete from DB once UID mappings are sent
    """
    table = dynamodb_resource.Table(table_name)
    response = table.scan(FilterExpression=Attr('notes').eq('senduid'))

    for ip in ipaddress_list:
        table.delete_item(Key={'username': ip})

    return


def uid_mapper(ipaddress, ctx):
    uidp = ""
    for ip in ipaddress:
        uid = uid_payload1 + ip + uid_payload2 + ip + uid_payload3
        uidp += uid

    cmd = fw_cmd1 + uidp + fw_cmd2

    response = urllib2.urlopen(cmd, context=ctx, timeout=5).read()
    print response
    return


def grp_mapper(ctx):
    fw_cmd1 = "https://" + gwMgmtIp + "/api/?type=user-id&action=set&key=" + apiKey + "&cmd=" + "%3Cuid-message%3E%3Cversion%3E1.0%3C/version%3E%3Ctype%3Eupdate%3C/type%3E%3Cpayload%3E%3Cgroups%3E%3Centry%20name=%22badusergroup%22%3E%3Cmembers%3E"
    grp_payload1 = "%3Centry%20name=%22"
    grp_payload2 = "%22/%3E"
    fw_cmd2 = "%3C/members%3E%3C/entry%3E%3C/groups%3E%3C/payload%3E%3C/uid-message%3E"

    table = dynamodb_resource.Table(table_name)
    response = table.scan()

    uidp = ""
    for user in response['Items']:
        uid = grp_payload1 + user['ipaddress'] + grp_payload2
        uidp += uid

    cmd = fw_cmd1 + uidp + fw_cmd2

    response = urllib2.urlopen(cmd, context=ctx, timeout=5).read()
    print response
    return


print('Loading Function')


def lambda_handler(event, context):
    count = check_item_count(table_name)
    if count > 0:
        ipaddress_list = read_from_db()
        grp_mapper(ctx)
        uid_mapper(ipaddress_list, ctx)
        update_db(ipaddress_list)
        # delete_from_db(ipaddress_list)
    return 'Completed uid mapping'