import boto3
from botocore.exceptions import ClientError
import json

iam_c = boto3.client('iam')
iam_r = boto3.resource('iam')


def generate_policy_document(s3buckets=None, snstopicarn=None):
    policy_template = None
    with open('installer/iam_policy_template.json', 'r') as policy_file:
        policy_template = json.loads(policy_file.read())

    bucketresources = []
    for bucket in s3buckets:
        bucketresources.append("arn:aws:s3:::{}".format(bucket))
        bucketresources.append("arn:aws:s3:::{}/*".format(bucket))
    policy_template['Statement'][3]['Resource'] = bucketresources

    if snstopicarn:
        policy_template['Statement'][4]['Resource'] = [snstopicarn]
    else:
        # don't need sns statement if there's no topic
        del policy_template['Statement'][4]
    return json.dumps(policy_template, indent=4)


def get_or_create_role(role_name):
    lambda_assume_role_policy_document = """{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "Service": "lambda.amazonaws.com"
          },
          "Action": "sts:AssumeRole"
        }
      ]
    }"""
    create_role = False
    role = iam_r.Role(role_name)
    try:
        role.load()
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print("Role doesn't exist, attempting to create")
            create_role = True
        else:
            print("Some other error occurred checking for the role, please review the error message below")
            print(e)

    if create_role:
        # create the role here
        try:
            print("Creating Role '{}'".format(role_name))
            role = iam_r.create_role(
                Path="/lambda-letsencrypt/",
                RoleName=role_name,
                AssumeRolePolicyDocument=lambda_assume_role_policy_document
            )
            print("Role Created")
        except ClientError as e:
            print("Error creating role")
            print(e)
            return None
    return role


def get_or_create_role_policy(role, policy_name, policy_document):
    create_role_policy = False
    role_policy = iam_r.RolePolicy(role.role_name, policy_name)
    try:
        role_policy.load()
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print("Role policy doesn't exist, attempting to create")
            create_role_policy = True
        else:
            print("Some other error occurred checking for the role policy, please review the error message below")
            print(e)

    if create_role_policy:
        iam_c.put_role_policy(
            RoleName=role.role_name,
            PolicyName=policy_name,
            PolicyDocument=policy_document
        )
        role_policy = iam_r.RolePolicy(role.role_name, policy_name)
        role_policy.load()

    return role_policy


def update_role_policy(role_policy, policy_document):
    if role_policy.policy_document != policy_document:
        try:
            role_policy.put(
                PolicyDocument=policy_document
            )
            return True
        except ClientError as e:
            print("An error occurred while updating the policy document")
            print(e)
            return False


def configure(role_name, policy_document):
    policy_name = "lambda-letsencrypt-policy"

    role = get_or_create_role(role_name)
    role_policy = get_or_create_role_policy(role, policy_name, policy_document)
    update_role_policy(role_policy, policy_document)

    return role.arn


def get_arn(role_name):
    role = iam_r.Role(role_name)
    try:
        role.load()
    except ClientError as e:
        return None
    return role.arn


def list_roles():
    roles = iam_c.list_roles()
    ret = []
    for x in roles['Roles']:
        ret.append(x['RoleName'])
    return ret
