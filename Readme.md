# Lambda Lets-Encrypt

Use [AWS Lambda](https://aws.amazon.com/lambda/) to manage SSL certificates for
any site that uses [Amazon's CloudFront CDN](https://aws.amazon.com/cloudfront/).

# Why do I want this?
Rather than having to dedicate a machine to running the Lets-Encrypt client to
maintain your certificate for your CloudFront distribution, you can let it all
live on Amazon's infrastructure for cheap. You'll receive notification if
anything goes wrong, and there's no hardware or virtual machines for you to
manage.

## How do I use this?
If you just want it to work and be done there is a wizard that will do all the
work for you. Or if you're more of a power user and want to see what all is
going on you can follow the steps to configure it manually.

### Automatic Wizard

1. Download this repo

2. Install the required dependency with `pip install boto3`

3. Save your AWS credentials:

    * install [`awscli`](https://aws.amazon.com/cli/) and run `aws configure`, **or**
    * manually create the file `~/.aws/credentials` with the following contents:

        ```ini
        [default]
        aws_access_key_id = YOUR_ACCESS_KEY
        aws_secret_access_key = YOUR_SECRET_KEY
        region = us-east-1 ; Replace with your region
        ```

4. Run `python wizard.py`
    
    This will

    * ask you a few questions about your desired set up
    * create a configuration file 
    * upload the lambda function for you
    * help you manually configure the lambda's daily scheduling (this can't be done automatically because there's no API yet)

### Manual Setup
More docs coming soon.

# How does it work?

This works by running a Lambda function once per day which will check
your certificate's expiration, and renew it if it is nearing expiration.

Since Lambda is billed in 100ms increments and this only needs to run once a day
for less than 10seconds each time the cost to run this is less than a
penny per month(i.e. effectively free)

## But I only have a static S3 website, how do I use this?
See the guide:
[Configuring a static S3 website to use CloudFront](./Readme_S3.md)

## Reporting Bugs/Feature Requests
The goal of this project is to make it as simple as possible for anyone to add
encryption to their (cloudfront hosted) website. Anything that makes you
uncertain should be
[filed as an issue](https://github.com/ubergeek42/lambda-lets-encrypt/issues).


## Special Thanks
I want to thank @diafygi for https://github.com/diafygi/acme-tiny, which I've
borrowed some code for so as not to need any python-openssl dependencies(which
isn't easily available in Lambda).

## Hacking

### Python Dependencies(for local development):
* boto3
* python-dateutil
