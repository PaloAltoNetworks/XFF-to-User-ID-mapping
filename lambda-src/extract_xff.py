import boto3
import botocore
import time
from boto3 import resource
from boto3 import client
import urllib2
import ssl
from xml.etree import ElementTree
import xml.etree.ElementTree as et
import os
import logging

client = boto3.client('dynamodb')
dynamodb_resource = resource('dynamodb')

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# Dynamodb tablename and the firewall management IP are passed in from the CFT template

table_name = os.environ['dbTable']
fwMgmtIP = os.environ['fwMgtIp']


apiKey = "LUFRPT1ETWtoUHduU0R5S0JpY0tvdktnQUFXNWlXR0k9TTlmMkhSMktNM25uM3hscXNnUXV3Zz09"

username = "baduser"
useridtimeout = "20"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
aggressive_mode = "DISABLE"

fw_cmd1 = "https://" + fwMgmtIP + "/api/?type=user-id&action=set&key=" + apiKey + "&cmd=" + "%3Cuid-message%3E%3Cversion%3E1.0%3C/version%3E%3Ctype%3Eupdate%3C/type%3E%3Cpayload%3E%3Clogin%3E%3Centry%20name=%22" + username + "%22%20ip=%22"
fw_cmd2 = "%22%20timeout=%22" + useridtimeout + "%22%3E%3C/entry%3E%3C/login%3E%3C/payload%3E%3C/uid-message%3E"

fw_url_log_cmd1 = "https://" + fwMgmtIP + "/api/?type=log&log-type=url&key=" + apiKey + "&query=((sessionid%20eq%20'"
fw_url_log_cmd2 = "')%20and%20(natsport%20eq%20'"
fw_url_log_cmd3 = "')%20and%20(receive_time%20geq%20'"
fw_url_log_cmd4 = "'))"

# fw_url_log_cmd1 = "https://"+fwMgmtIP+"/api/?type=log&log-type=url&key="+apiKey+"&query=((sessionid%20eq%20'"
# fw_url_log_cmd2 = "')%20and%20(natsport%20eq%20'"
# fw_url_log_cmd3 = "'))"

fw_url_xff_cmd = "https://" + fwMgmtIP + "/api/?type=log&action=get&key=" + apiKey + "&job-id="


def ttl_status(table_name):
    """
    Validate the TTL status on the table.
    """
    response = client.describe_time_to_live(TableName=table_name)
    if response['TimeToLiveDescription']['TimeToLiveStatus'] == "DISABLED":
        return "DISABLED"
    return "ENABLED"


def update_ttl_status(table_name):
    """
    Enable TTL Specification on the table and modify the TTL attribute to "expirationdate" column name from the table
    """
    response = client.update_time_to_live(TableName=table_name,
                                          TimeToLiveSpecification={'Enabled': True, 'AttributeName': 'expirationdate'})
    return response


def add_item(table_name, col_dict):
    """
    Add one item (row) to table. col_dict is a dictionary {col_name: value}.
    """
    table = dynamodb_resource.Table(table_name)
    response = table.put_item(Item=col_dict)

    return response


def write_to_s3(line):
    s3 = boto3.resource('s3')
    exists = False
    print "Writing to S3"
    try:
        s3.Object('xffholder', 'xff.txt').load()
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            exists = False
            s3.Object('xffholder', 'xff.txt').put(Body=line)
            object_acl = s3.ObjectAcl('xffholder', 'xff.txt')
            response = object_acl.put(ACL='public-read')
        else:
            raise
    else:
        obj = s3.Object('xffholder', 'xff.txt')
        contents = obj.get()['Body'].read()
        contents += "\n" + line
        obj.put(Body=contents)
        object_acl = s3.ObjectAcl('xffholder', 'xff.txt')
        response = object_acl.put(ACL='public-read')

    return


def check_item_count(table_name):
    table = dynamodb_resource.Table(table_name)
    count = table.scan()['Count']
    return count


def write_to_db(ipaddress):
    """
    Write IP Address, Username, Creation and Expiration Date to Dynamo DB
    """
    print "Writing to DB"
    creationdate = int(time.time())
    expirationdate = int(time.time()) + 86400
    col_dict = {"username": ipaddress, "ipaddress": ipaddress, "creationdate": creationdate,
                "expirationdate": expirationdate, "notes": "senduid"}
    add_item(table_name, col_dict)
    line = ipaddress + "," + str(creationdate)
    return line


def uid_mapper(ipaddress, ctx):
    cmd = fw_cmd1 + ipaddress + fw_cmd2

    response = urllib2.urlopen(cmd, context=ctx, timeout=5).read()
    print response
    return


def url_log_jobid_extracter1(sessionid, natsport, rxtime, ctx):
    cmd = fw_url_log_cmd1 + str(sessionid) + fw_url_log_cmd2 + str(natsport) + fw_url_log_cmd3 + rxtime.split(" ")[
        0] + "%20" + rxtime.split(" ")[1] + fw_url_log_cmd4
    print "The command to extract jobid is", cmd

    logger.info('[INFO]: Sending command: %s', cmd)
    try:
        response = urllib2.urlopen(cmd, context=ctx, timeout=5).read()
        # Now we do stuff to the gw
        logger.info("[RESPONSE] in send command: {}".format(response))
        resp_header = et.fromstring(response)
        if resp_header.tag != 'response':
            logger.info("[ERROR]: didn't get a valid response from firewall")
            return 'false'
        if resp_header.attrib['status'] == 'success':
            # The fw responded with a successful command execution. No need to check what the actual response is
            logger.info("[INFO]: Successfully executed command")

    except:
        logger.info("[ERROR]: Something bad happened when sending command")
        return 'false'

    dom = ElementTree.fromstring(response)

    jobid = dom[0].find('job').text
    return jobid


def url_log_jobid_extracter(sessionid, natsport, ctx):
    cmd = fw_url_log_cmd1 + str(sessionid) + fw_url_log_cmd2 + str(natsport) + fw_url_log_cmd3
    print "The command to extract jobid is", cmd

    logger.info('[INFO]: Sending command: %s', cmd)
    try:
        response = urllib2.urlopen(cmd, context=ctx, timeout=5).read()
        # Now we do stuff to the gw
        logger.info("[RESPONSE] in send command: {}".format(response))
        resp_header = et.fromstring(response)
        if resp_header.tag != 'response':
            logger.info("[ERROR]: didn't get a valid response from firewall")
            return 'false'
        if resp_header.attrib['status'] == 'success':
            # The fw responded with a successful command execution. No need to check what the actual response is
            logger.info("[INFO]: Successfully executed command")

    except:
        logger.info("[ERROR]: Something bad happened when sending command")
        return 'false'

    dom = ElementTree.fromstring(response)

    jobid = dom[0].find('job').text
    return jobid


def xff_extracter(jobid, ctx):
    cmd = fw_url_xff_cmd + str(jobid)
    print "The command to extract XFF is", cmd
    logger.info('[INFO]: Sending command: %s', cmd)
    try:
        response = urllib2.urlopen(cmd, context=ctx, timeout=5).read()
        # Now we do stuff to the gw
        logger.info("[RESPONSE] in send command: {}".format(response))
        resp_header = et.fromstring(response)
        if resp_header.tag != 'response':
            logger.info("[ERROR]: didn't get a valid response from firewall")
            return 'false'
        if resp_header.attrib['status'] == 'success':
            # The fw responded with a successful command execution. No need to check what the actual response is
            logger.info("[INFO]: Successfully executed command")

    except:
        logger.info("[ERROR]: Something bad happened when sending command")
        return 'false'


    dom = ElementTree.fromstring(response)

    if dom[0][1][0].attrib['count'] == "0":
        return "RETRY"
    else:
        xff = dom.find('./result/log/logs/entry/xff').text
        return xff


print('Loading Function')


def extract_xff_lambda_handler(event, context):
    count = 0

    sessionid = event['sessionid']
    if sessionid == None:
        logger.info("[ERROR]: didn't get sessionid")
        return
    print('Session id is:', sessionid)

    natsport = event['natsrcport']
    if natsport == None:
        logger.info("[ERROR]: didn't get natsport")
        return
    print("NAT SPORT is:", natsport)

    rxtime = event['rxtime']
    if rxtime == None:
        logger.info("[ERROR]: didn't get rxtime")
        return
    print("Receive time is:", rxtime)

    if ttl_status(table_name) == "DISABLED":
        update_ttl_status(table_name)

    while count < 5:
        jobid = url_log_jobid_extracter1(sessionid, natsport, rxtime, ctx)
        print('Job id is:', jobid)
        print("Sleeping for 2 second...")
        time.sleep(3)
        xff = xff_extracter(jobid, ctx)
        if xff == "RETRY":
            count += 1
        else:
            count = 6
            print("XFF extracted is", xff)
            line = write_to_db(xff)
            print("Line is: ", line)


            ###ipaddress = event['ipaddress']

            ###print("The XFF header IP is ", ipaddress)
            # write_to_s3(ipaddress)



            # currtime = int(time.time())
            # fiveminago = currtime - 300

            # if check_item_count(table_name) > 1:

            # write_to_db(ipaddress)
            # if aggressive_mode == "ENABLE":
            #   uid_mapper(ipaddress,ctx)
            # else:
            #   write_to_db(ipaddress)

    return 'Completed uid mapping'