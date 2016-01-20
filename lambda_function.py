from __future__ import print_function
import logging
import datetime
from time import strftime, gmtime, sleep
from dateutil.tz import tzutc
from simple_acme import AcmeUser, AcmeAuthorization, AcmeCert
from functools import partial
import urllib2

# aws imports
import boto3
import botocore

# Configure logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger("Lambda-LetsEncrypt")
logger.setLevel(logging.DEBUG)


import config as cfg

###############################################################################
# No need to edit beyond this line
###############################################################################

# Global Variables and AWS Resources
s3 = boto3.resource('s3', region_name=cfg.AWS_REGION)
cloudfront = boto3.client('cloudfront', region_name=cfg.AWS_REGION)
iam = boto3.client('iam', region_name=cfg.AWS_REGION)
sns = boto3.client('sns', region_name=cfg.AWS_REGION)
elb = boto3.client('elb', region_name=cfg.AWS_REGION)
route53 = boto3.client('route53', region_name=cfg.AWS_REGION)

# Internal files to store user/authorization information
USERFILE = 'letsencrypt_user.json'
AUTHZRFILE = 'letsencrypt_authzr.json'


# Functions for storing/retrieving/deleting files from our config bucket
def save_file(site_id, filename, content):
    s3.Object(cfg.S3CONFIGBUCKET, site_id + "/" + filename).put(Body=content)


def load_file(directory, filename):
    try:
        obj = s3.Object(cfg.S3CONFIGBUCKET, directory + "/" + filename).get()
        return obj['Body'].read()
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            return False
        return False


# Verify the bucket exists
def check_bucket(bucketname):
    try:
        s3.meta.client.head_bucket(Bucket=bucketname)
        exists = True
    except botocore.exceptions.ClientError as e:
        error_code = int(e.response['Error']['Code'])
        if error_code == 404:
            exists = False
        # TODO: handle other errors better
        exists = False
    return exists


def get_user():
    # Generate a user key to use with letsencrypt
    userfile = load_file('letsencrypt', USERFILE)
    user = None
    if userfile is not False:
        logger.info("User key exists, loading...")
        user = AcmeUser.unserialize(userfile)
        user.register(cfg.EMAIL)
    else:
        logger.info("Creating user and key")
        user = AcmeUser(keybits=cfg.USERKEY_BITS)
        user.create_key()
        user.register(cfg.EMAIL)
        save_file('letsencrypt', USERFILE, user.serialize())
    return user


def notify_email(subject, message):
    if cfg.SNS_TOPIC_ARN:
        logger.info("Sending notification")
        sns.publish(
            TopicArn=cfg.SNS_TOPIC_ARN,
            Subject="[Lambda-LetsEncrypt] {}".format(subject),
            Message=message
        )


def s3_challenge_solver(domain, token, keyauth, bucket=None, prefix=None):
    # logger.info("Writing file {} with content '{}.{}' for domain '{}'".format(token, token, keyauth, domain))
    logger.info("Got prefix {}".format(prefix))
    filename = "{}/.well-known/acme-challenge/{}".format(prefix, token)
    logger.info("Writing {} into S3 Bucket {}".format(filename, bucket))

    expires = datetime.datetime.now() + datetime.timedelta(days=3)
    s3.Object(bucket, filename).put(
        Body=keyauth,
        Expires=expires
    )
    return True


def http_challenge_verifier(domain, token, keyauth):
    url = "http://{}/.well-known/acme-challenge/{}".format(domain, token)
    try:
        response = urllib2.urlopen(url)
        contents = response.read()
        code = response.getcode()
    except Exception as e:
        logger.warn("Failed to verify:")
        logger.warn(e)
        return False

    if code != 200:
        logger.warn("HTTP code {} returned, expected 200".format(code))
        return False
    if contents != keyauth:
        logger.warn("Validation body didn't match, expected '{}', got '{}'".format(keyauth, contents))
        return False

    return True


def route53_challenge_solver(domain, token, keyauth, zoneid=None):
    route53.change_resource_record_sets(
        HostedZoneId=zoneid,
        ChangeBatch={
            'Comment': "Lamdba LetsEncrypt DNS Challenge Response",
            'Changes': [{
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': '_acme-challenge.{}'.format(domain),
                    'Type': 'TXT',
                    'TTL': 300,
                    'ResourceRecords': [{
                        'Value': '"{}"'.format(keyauth)
                    }]
                }
            }]
        }

    )
    return True


def route53_challenge_verifier(domain, token, keyauth):
    # TODO: this isn't implemented yet.
    # XXX: DNS propagation may make this somewhat time consuming.
    # try to resolve record '_acme-challenge.domain' and verify that the txt record value matches 'keyauth'
    pass


def authorize_domain(user, domain):
    authzrfilename = 'authzr-{}.json'.format(domain)
    authzrfile = load_file(domain['DOMAIN'], authzrfilename)
    if authzrfile is not False:
        authzr = AcmeAuthorization.unserialize(user, authzrfile)
    else:
        authzr = AcmeAuthorization(user=user, domain=domain['DOMAIN'])
    status = authzr.authorize()

    # save the (new/updated) authorization response
    save_file(domain['DOMAIN'], authzrfilename, authzr.serialize())
    logger.debug(authzr.serialize())

    # see if we're done
    if status == 'pending':
        if 'http-01' in domain['VALIDATION_METHODS']:
            logger.info("Attempting challenge 'http-01'")
            authzr.complete_challenges(
                "http-01",
                partial(s3_challenge_solver, bucket=cfg.S3CHALLENGEBUCKET, prefix=domain['CLOUDFRONT_ID']),
                http_challenge_verifier
            )
        if 'dns-01' in domain['VALIDATION_METHODS']:
            logger.info("Attempting challenge 'dns-01'")
            authzr.complete_challenges(
                "dns-01",
                partial(route53_challenge_solver, zoneid=domain['ROUTE53_ZONE_ID']),
                route53_challenge_verifier
            )
        logger.info("Waiting for challenge to be confirmed for '{}'".format(domain['DOMAIN']))
        return False
    elif status == 'valid':
        logger.info("Got domain authorization for: {}".format(domain['DOMAIN']))
        return authzr
    else:  # probably failed the challenge
        logger.warn("Some error happend with authz request for '{}'(review above messages)".format(domain['DOMAIN']))
        logger.warn("Will retry again next time this runs")
        return False


def iam_upload_cert(certname, cert, key, chain):
        # upload new cert
        try:
            newcert = iam.upload_server_certificate(
                Path="/letsencrypt_lambda/",
                ServerCertificateName=certname,
                CertificateBody=cert,
                PrivateKey=key,
                CertificateChain=chain
            )
            cert_id = newcert['ServerCertificateMetadata']['ServerCertificateId']
            cert_arn = newcert['ServerCertificateMetadata']['Arn']
            logger.info("Uploaded cert '{}' ({})".format(certname, cert_id))
            return cert_id, cert_arn
        except botocore.exceptions.ClientError as e:
            logger.error("Error uploading iam cert:")
            logger.error(e)
            return False


def iam_delete_cert(arn=None, cert_id=None):
    oldcert_name = None
    allcerts = iam.list_server_certificates(
        PathPrefix="/letsencrypt_lambda/"
    )
    for c in allcerts['ServerCertificateMetadataList']:
        if c['ServerCertificateId'] == cert_id or c['Arn'] == arn:
            oldcert_name = c['ServerCertificateName']
            break
    if not oldcert_name:
        logger.warn('Unable to find old certificate to delete')
        return
    logger.info('Deleting old certificate {}'.format(oldcert_name))
    retries = 5
    while retries > 0:
        try:
            iam.delete_server_certificate(ServerCertificateName=oldcert_name)
            return
        except botocore.exceptions.ClientError as e:
            # we only retry if it said cert deleteconflict since it may take a few moments
            # for something to stop using the certificate(e.g. elb)
            if e.response['Error']['Code'] == 'DeleteConflict':
                logger.info("Cert in use while trying to delete, retrying...")
                sleep(5)
                continue

            logger.error("Unknown error occurred while deleting certificate")
            logger.error(e)
            notify_email(
                "Unable to delete certificate",
                """Lambda-LetsEncrypt failed to delete the certificate '{}'. You should manually do this yourself""".format(oldcert_name)
            )
            break


def iam_check_expiration(arn=None, cert_id=None):
    allcerts = iam.list_server_certificates(PathPrefix="/letsencrypt_lambda/")
    expiration = None
    cert = None
    for c in allcerts['ServerCertificateMetadataList']:
        if c['ServerCertificateId'] == cert_id or c['Arn'] == arn:
            cert = c
            break
    if not cert:
        # no expiration found?
        return True
    expiration = cert['Expiration']
    time_left = expiration - datetime.datetime.now(tz=tzutc())

    if time_left.days < 10:
        logger.warn("Only {} days left on cert {}!".format(time_left.days, cert['ServerCertificateName']))
        notify_email(
            'Less than 10 days left on cert {}'.format(cert['ServerCertificateName']),
            """
There's less than 10 days left on your certificate for {}. This probably
means the lambda function that is supposed to be handling the renewal is
failing. Please check the logs for it. Attempting to renew now.
""".format(cert['ServerCertificateName'])
        )
        return True
    elif time_left.days < 30:
        logger.info("Only {} days remaining, will proceed with renewal for {}".format(time_left.days, cert['ServerCertificateName']))
        return True
    else:
        logger.info("{} days remaining on cert, nothing to do for {}.".format(time_left.days, cert['ServerCertificateName']))
        return False


def is_elb_cert_expiring(site):
    return True
    try:
        load_balancers = elb.describe_load_balancers(
            LoadBalancerNames=[site['ELB_NAME']],
        )
    except botocore.exceptions.ClientError as e:
        logger.error("Error getting information about Elastic Load Balancer '{}'".format(site['ELB_NAME']))
        logger.error(e)
        return False

    currentcert_arn = None
    for lb in load_balancers['LoadBalancerDescriptions']:
        if lb['LoadBalancerName'] != site['ELB_NAME']:
            continue
        for listener in lb['ListenerDescriptions']:
            if listener['Listener']['LoadBalancerPort'] != site['ELB_PORT']:
                continue
            if 'SSLCertificateId' in listener['Listener']:
                currentcert_arn = listener['Listener']['SSLCertificateId']
    if currentcert_arn is None:
        logger.info("No certificate exists for elb name {}".format(site['ELB_NAME']))
    return iam_check_expiration(arn=currentcert_arn)


def is_cf_cert_expiring(site):
    cf_config = cloudfront.get_distribution_config(Id=site['CLOUDFRONT_ID'])
    currentcert = cf_config['DistributionConfig']['ViewerCertificate'].get('IAMCertificateId', None)

    if currentcert is None:
        logger.info("No certificate exists for {}".format(site['CLOUDFRONT_ID']))
        return True

    return iam_check_expiration(cert_id=currentcert)


def is_domain_expiring(site):
    if 'CLOUDFRONT_ID' in site:
        return is_cf_cert_expiring(site)
    if 'ELB_NAME' in site:
        return is_elb_cert_expiring(site)
    logger.error("Can't detect site type(ELB or CLOUDFRONT)")
    return False


def configure_cert(site, cert, key, chain):
    certname = "{}_{}".format(site_id(site), strftime("%Y%m%d_%H%M%S", gmtime()))
    cert_id, cert_arn = iam_upload_cert(certname, cert, key, chain)

    f = None
    if 'CLOUDFRONT_ID' in site:
        f = cloudfront_configure_cert
    if 'ELB_NAME' in site:
        f = elb_configure_cert
    if f is None:
        logger.error("Can't detect site type when configuring certificate(ELB or CLOUDFRONT)")

    ret = False
    retries = 5
    while retries > 0:
        retries -= 1
        try:
            ret = f(site, cert_id, cert_arn)
            break
        except botocore.exceptions.ClientError as e:
            # we only retry if it said cert not found
            if e.response['Error']['Code'] == 'CertificateNotFound':
                logger.info("Cert not found when trying to configure ELB, retrying...")
                sleep(5)
                continue

            logger.error("Unknown error occurred while updating certificate")
            logger.error(e)
            ret = False
            break

    return ret


def elb_configure_cert(site, cert_id, cert_arn):
    # get the current certificate for the load balancer(if there is one)
    load_balancers = elb.describe_load_balancers(
        LoadBalancerNames=[site['ELB_NAME']],
    )
    oldcert_arn = None
    for lb in load_balancers['LoadBalancerDescriptions']:
        if lb['LoadBalancerName'] != site['ELB_NAME']:
            continue

        for listener in lb['ListenerDescriptions']:
            if listener['Listener']['LoadBalancerPort'] != site['ELB_PORT']:
                continue
            if 'SSLCertificateId' in listener['Listener']:
                oldcert_arn = listener['Listener']['SSLCertificateId']

    # if there wasn't an old cert, we need to configure the elb for HTTPS
    if oldcert_arn is None:
        logger.info("No listener exists for specified port, creating default")
        # create a load balancer policy
        logger.debug("Creating load balancer policy")
        elb.create_load_balancer_policy(
            LoadBalancerName=site['ELB_NAME'],
            PolicyName="lambda-letsencrypt-default-ssl-policy",
            PolicyTypeName="SSLNegotiationPolicyType",
            PolicyAttributes=[{
                'AttributeName': 'Reference-Security-Policy',
                'AttributeValue': 'ELBSecurityPolicy-2015-05'
            }]
        )
        # create a load balancer listener
        logger.debug("Creating load balancer listener")
        elb.create_load_balancer_listeners(
            LoadBalancerName=site['ELB_NAME'],
            Listeners=[{
                'Protocol': 'HTTPS',
                'LoadBalancerPort': site['ELB_PORT'],
                'InstanceProtocol': 'HTTP',
                'InstancePort': 80,
                'SSLCertificateId': cert_arn
            }]
        )
        # associate policy with the listener
        logger.debug("Setting load balancer listener policy")
        elb.set_load_balancer_policies_of_listener(
            LoadBalancerName=site['ELB_NAME'],
            LoadBalancerPort=site['ELB_PORT'],
            PolicyNames=['lambda-letsencrypt-default-ssl-policy']
        )
    # Set up the new certificate
    elb.set_load_balancer_listener_ssl_certificate(
        LoadBalancerName=site['ELB_NAME'],
        LoadBalancerPort=site['ELB_PORT'],
        SSLCertificateId=cert_arn
    )

    # Delete the old certificate if it existed
    if oldcert_arn:
        iam_delete_cert(arn=oldcert_arn)

    return True


def cloudfront_configure_cert(site, cert_id, cert_arn):
    # get current cloudfront distribution settings
    cf_config = cloudfront.get_distribution_config(Id=site['CLOUDFRONT_ID'])
    oldcert_id = cf_config['DistributionConfig']['ViewerCertificate'].get('IAMCertificateId', None)

    # Make sure the default cloudfront cert isn't being used
    if 'CloudFrontDefaultCertificate' in cf_config['DistributionConfig']['ViewerCertificate']:
        del cf_config['DistributionConfig']['ViewerCertificate']['CloudFrontDefaultCertificate']

    # update it to point to the new cert
    cf_config['DistributionConfig']['ViewerCertificate']['IAMCertificateId'] = cert_id
    cf_config['DistributionConfig']['ViewerCertificate']['Certificate'] = cert_id
    cf_config['DistributionConfig']['ViewerCertificate']['CertificateSource'] = 'iam'
    # make sure we use SNI only(otherwise the bill can be quite large, $600/month or so)
    cf_config['DistributionConfig']['ViewerCertificate']['MinimumProtocolVersion'] = 'TLSv1'
    cf_config['DistributionConfig']['ViewerCertificate']['SSLSupportMethod'] = 'sni-only'

    # actually update the distribution
    cloudfront.update_distribution(
        DistributionConfig=cf_config['DistributionConfig'],
        Id=site['CLOUDFRONT_ID'],
        IfMatch=cf_config['ETag']
    )

    # delete the old cert
    iam_delete_cert(cert_id=oldcert_id)
    return True


def configure_cloudfront(domain, s3bucket):
    cf_config = cloudfront.get_distribution_config(Id=domain['CLOUDFRONT_ID'])
    changed = False
    # make sure we have the origin configured
    origins = cf_config['DistributionConfig']['Origins']['Items']
    # check for the right origin
    challenge_origin = [x for x in origins if x['Id'] == 'lambda-letsencrypt-challenges']
    if not challenge_origin:
        changed = True
        quantity = cf_config['DistributionConfig']['Origins'].get('Quantity', 0)
        cf_config['DistributionConfig']['Origins']['Quantity'] = quantity + 1
        cf_config['DistributionConfig']['Origins']['Items'].append({
            'DomainName': '{}.s3.amazonaws.com'.format(s3bucket),
            'Id': 'lambda-letsencrypt-challenges',
            'OriginPath': "/{}".format(domain['CLOUDFRONT_ID']),
            'S3OriginConfig': {u'OriginAccessIdentity': ''}
        })

    # now check for the behavior rule
    behaviors = cf_config['DistributionConfig']['CacheBehaviors'].get('Items', [])
    challenge_behavior = [x for x in behaviors if x['PathPattern'] == '/.well-known/acme-challenge/*']
    if not challenge_behavior:
        changed = True
        if 'Items' not in cf_config['DistributionConfig']['CacheBehaviors']:
            cf_config['DistributionConfig']['CacheBehaviors']['Items'] = []
        cf_config['DistributionConfig']['CacheBehaviors']['Items'].append({
            'AllowedMethods': {
                'CachedMethods': {
                    'Items': ['HEAD', 'GET'],
                    'Quantity': 2
                },
                'Items': ['HEAD', 'GET'],
                'Quantity': 2
            },
            'DefaultTTL': 86400,
            'ForwardedValues': {
                u'Cookies': {u'Forward': 'none'},
                'Headers': {'Quantity': 0},
                'QueryString': False
            },
            'MaxTTL': 31536000,
            'MinTTL': 0,
            'PathPattern': '/.well-known/acme-challenge/*',
            'SmoothStreaming': False,
            'TargetOriginId': 'lambda-letsencrypt-challenges',
            'TrustedSigners': {u'Enabled': False, 'Quantity': 0},
            'ViewerProtocolPolicy': 'allow-all',
            'Compress': False
        })
        quantity = cf_config['DistributionConfig']['CacheBehaviors'].get('Quantity', 0)
        cf_config['DistributionConfig']['CacheBehaviors']['Quantity'] = quantity + 1

    # make sure we use SNI and not dedicated IP($600/month)
    #ssl_method = cf_config['DistributionConfig']['ViewerCertificate'].get('SSLSupportMethod', None)
    #if ssl_method != 'sni-only':
    #    changed = True
    #    cf_config['DistributionConfig']['ViewerCertificate']['MinimumProtocolVersion'] = 'TLSv1'
    #    cf_config['DistributionConfig']['ViewerCertificate']['SSLSupportMethod'] = 'sni-only'

    if changed:
        logger.info("Updating cloudfront distribution with additional origin for challenges")
        #  now save that config back
        try:
            cloudfront.update_distribution(
                DistributionConfig=cf_config['DistributionConfig'],
                Id=domain['CLOUDFRONT_ID'],
                IfMatch=cf_config['ETag']
            )
        except Exception as e:
            logger.error("Error updating cloudfront distribution")
            logger.error(e)


def site_name(site):
    if 'CLOUDFRONT_ID' in site:
        return "CloudFront Distribution '{}'".format(site['CLOUDFRONT_ID'])
    elif 'ELB_NAME' in site:
        return "ELB Name '{}'".format(site['ELB_NAME'])


def site_id(site):
    if 'CLOUDFRONT_ID' in site:
        return "cfd-{}".format(site['CLOUDFRONT_ID'])
    elif 'ELB_NAME' in site:
        return 'elb-{}'.format(site['ELB_NAME'])


def lambda_handler(event, context):
    action_needed = False
    # Do a few sanity checks
    if not check_bucket(cfg.S3CONFIGBUCKET):
        logger.error("S3 configuration bucket does not exist")
        # TODO: maybe send email?
        return False

    if not check_bucket(cfg.S3CHALLENGEBUCKET):
        logger.error("S3 challenge bucket does not exist")
        # TODO: maybe send email?
        return False

    # check the certificates we want issued
    for site in cfg.SITES:
        if not is_domain_expiring(site):
            site['skip'] = True
            continue
        action_needed = True

    # quit if there's nothing to do
    if not action_needed:
        return False

    # get our user key to use with lets-encrypt
    user = get_user()

    # validate domains
    my_domains = []
    for domain in cfg.DOMAINS:
        # make sure cloudfront is configured properly for http-01 challenge validation
        if 'http-01' in domain['VALIDATION_METHODS']:
            configure_cloudfront(domain, cfg.S3CHALLENGEBUCKET)

        authzr = authorize_domain(user, domain)
        if authzr:
            my_domains.append(domain['DOMAIN'])

    for site in cfg.SITES:
        if 'skip' in site:
            continue
        # check that we are authed for all the domains for this site
        if not set(site['DOMAINS']).issubset(my_domains):
            logger.info("Can't get cert for {}, still waiting on domain authorizations".format(site_name(site)))
            continue

        try:
            # Now that we're authorized to get certs for the domain(s), lets generate
            # a private key and a csr, then use them to get a certificate
            logger.info("Generate CSR and get cert for {}".format(site_name(site)))
            pkey, csr = AcmeCert.generate_csr(cfg.CERT_BITS, site['DOMAINS'])
            cert, cert_chain = AcmeCert.get_cert(user, csr)

            # With our certificate in hand we can update the site configuration
            ret = configure_cert(site, cert, pkey, cert_chain)
            if ret:
                notify_email("Certificate issued",
                             "The certificate for {} has been successfully updated".format(site_name(site)))
            else:
                notify_email("Error issuing cert",
                             "There was some sort of error configuring the site({}) with the certificate.".format(site_name(site)) +
                             "Please review the logs in cloudwatch.")
        except Exception as e:
            logger.warning(e)

# Support running directly for testing
if __name__ == '__main__':
    lambda_handler(None, None)
