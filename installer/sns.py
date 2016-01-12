import boto3
from botocore.exceptions import ClientError


def get_or_create_topic(email):
    topicname = "letsencrypt-lambda-notify"
    sns_r = boto3.resource('sns')
    sns_c = boto3.client('sns')

    # If the topic doesn't exist, this will create it, otherwise it returns
    # the existing topic.
    topic = sns_c.create_topic(Name=topicname)
    topic_arn = topic['TopicArn']

    # subscribe the email to the topic
    sns_c.subscribe(
        TopicArn=topic_arn,
        Protocol='email',
        Endpoint=email
    )
    return topic_arn
