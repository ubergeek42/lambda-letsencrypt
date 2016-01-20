import boto3
from botocore.exceptions import ClientError

route53_c = boto3.client('route53')


def list_zones():
    elbs = route53_c.list_hosted_zones()
    ret = []
    for x in elbs['HostedZones']:
        ret.append({
            'Id': x['Id'],
            'Name': x['Name'].rstrip('.')  # remove trailing dots
        })
    return ret


def get_zone_id(zone):
    zone = zone.rstrip(".")  # remove any possible trailing dots
    zones = list_zones()
    return next((z['Id'] for z in zones if z['Name'] == zone), None)
