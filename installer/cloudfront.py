import boto3
from botocore.exceptions import ClientError
cloudfront_c = boto3.client('cloudfront')


def list_distributions():
    dl = cloudfront_c.list_distributions()
    ret = []
    if 'Items' not in dl['DistributionList']:
        return ret
    for dist in dl['DistributionList']['Items']:
        ret.append({
            'Id': dist['Id'],
            'Comment': dist['Comment'],
            'Aliases': dist['Aliases'].get('Items', [])
        })
    return ret
