import boto3
from botocore.exceptions import ClientError

elb_c = boto3.client('elb')

def list_elbs():
    elbs = elb_c.describe_load_balancers()
    ret = []
    for x in elbs['LoadBalancerDescriptions']:
        ret.append(x['LoadBalancerName'])
    return ret
