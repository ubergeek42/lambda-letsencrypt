import boto3
from botocore.exceptions import ClientError
lambda_c = boto3.client('lambda')


def create_function(name, iam_role, archive, handler='lambda_function.lambda_handler'):
    with open(archive, 'rb') as f:
        contents = f.read()
    try:
        lambda_c.create_function(
            FunctionName=name,
            Runtime='python2.7',
            Role=iam_role,
            Handler=handler,
            Code={
                'ZipFile': contents
            },
            Description='Lambda Function for AWS Lets-Encrypt',
            Timeout=30,
            MemorySize=128,
            Publish=True
        )
    except Exception as e:
        print(e)
        return False

    return True


def list_distributions():
    dl = cloudfront_c.list_distributions()
    ret = []
    for dist in dl['DistributionList']['Items']:
        ret.append({
            'Id': dist['Id'],
            'Comment': dist['Comment'],
            'Aliases': dist['Aliases'].get('Items', [])
        })
    return ret
