import boto3
from botocore.exceptions import ClientError
import string

s3_c = boto3.client('s3')
s3_r = boto3.resource('s3')

WEB_POLICY_DOC = string.Template("""\
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "$arn/*"
        }
    ]
}
""")


def s3_list_buckets():
    buckets = s3_c.list_buckets()
    ret = []
    for x in buckets['Buckets']:
        ret.append(x['Name'])
    return ret


def create_bucket(bucket_name):
    bucket = s3_r.create_bucket(
        Bucket=bucket_name,
        ACL="private"
    )
    return bucket


def create_web_bucket(bucket_name):
    bucket = create_bucket(bucket_name)
    bucket_policy = bucket.Policy()
    bucket_arn = "arn:aws:s3:::{}".format(bucket_name)
    bucket_policy.put(Policy=WEB_POLICY_DOC.substitute(arn=bucket_arn))

    webconfig = bucket.Website()
    webconfig.put(
        WebsiteConfiguration={
            'ErrorDocument': {'Key': '404.html'},
            'IndexDocument': {'Suffix': 'index.html'},
        }
    )
    return bucket
