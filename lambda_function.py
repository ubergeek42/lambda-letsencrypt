from __future__ import print_function
import logging
import datetime
from time import strftime, gmtime
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
logger.setLevel(logging.INFO)


import config as cfg

###############################################################################
# No need to edit beyond this line
###############################################################################

# Global Variables and AWS Resources
s3 = boto3.resource('s3', region_name=cfg.AWS_REGION)
cloudfront = boto3.client('cloudfront', region_name=cfg.AWS_REGION)
iam = boto3.client('iam', region_name=cfg.AWS_REGION)
sns = boto3.client('sns', region_name=cfg.AWS_REGION)


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


def delete_file(directory, filename):
    obj = s3.Object(cfg.S3CONFIGBUCKET, site_id + "/" + filename).delete()


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


def route53_challenge_solver(domain, token, keyauth):
    logger.error("Not implemented yet")
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
        authzr.complete_challenges(
            "http-01",
            partial(s3_challenge_solver, bucket=cfg.S3CHALLENGEBUCKET, prefix=domain['CLOUDFRONT_ID']),
            http_challenge_verifier
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


def cloudfront_configure_cert(site, cert, key, chain):
    # upload new cert
    certname = "{}_{}".format(site['CLOUDFRONT_ID'], strftime("%Y%m%d_%H%M%S", gmtime()))
    try:
        newcert = iam.upload_server_certificate(
            Path="/cloudfront/{}/".format(certname),
            ServerCertificateName=certname,
            CertificateBody=cert,
            PrivateKey=key,
            CertificateChain=chain
        )
        servercertid = newcert['ServerCertificateMetadata']['ServerCertificateId']
        logger.info("Uploaded cert '{}' ({})".format(certname, servercertid))
    except botocore.exceptions.ClientError as e:
        logger.error("Error uploading iam cert: {}".format(e))
        return False

    # get current cloudfront distribution settings
    cf_config = cloudfront.get_distribution_config(Id=site['CLOUDFRONT_ID'])
    oldcert = cf_config['DistributionConfig']['ViewerCertificate'].get('IAMCertificateId', None)

    # Make sure the default cloudfront cert isn't being used
    if 'CloudFrontDefaultCertificate' in cf_config['DistributionConfig']['ViewerCertificate']:
        del cf_config['DistributionConfig']['ViewerCertificate']['CloudFrontDefaultCertificate']

    # update it to point to the new cert
    cf_config['DistributionConfig']['ViewerCertificate']['IAMCertificateId'] = servercertid
    cf_config['DistributionConfig']['ViewerCertificate']['Certificate'] = servercertid
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

    # search for the old cert and delete it
    oldcert_name = None
    allcerts = iam.list_server_certificates(
        PathPrefix="/cloudfront/{}".format(site['CLOUDFRONT_ID'])
    )
    for c in allcerts['ServerCertificateMetadataList']:
        if c['ServerCertificateId'] == oldcert:
            oldcert_name = c['ServerCertificateName']
            break
    if oldcert_name:
        logger.info('Deleting old certificate {}'.format(oldcert_name))
        iam.delete_server_certificate(ServerCertificateName=oldcert_name)
    return True


def cert_needs_renewal(site):
    cf_config = cloudfront.get_distribution_config(Id=site['CLOUDFRONT_ID'])
    currentcert = cf_config['DistributionConfig']['ViewerCertificate'].get('IAMCertificateId', None)

    if currentcert is None:
        logger.info("No certificate exists for {}".format(site['CLOUDFRONT_ID']))
        return True

    allcerts = iam.list_server_certificates(PathPrefix="/cloudfront/{}".format(site['CLOUDFRONT_ID']))
    expiration = None
    for c in allcerts['ServerCertificateMetadataList']:
        if c['ServerCertificateId'] == currentcert:
            expiration = c['Expiration']
            break
    if not expiration:
        # no expiration found?
        return True

    time_left = expiration - datetime.datetime.now(tz=tzutc())

    if time_left.days < 10:
        logger.warn("Only {} days left on cert for {}!".format(time_left.days, site['CLOUDFRONT_ID']))
        notify_email(
            'Less than 10 days left on cert for {}'.format(site['CLOUDFRONT_ID']),
            """
There's less than 10 days left on your certificate for {}. This probably
means the lambda function that is supposed to be handling the renewal is
failing. Please check the logs for it. Attempting to renew now.
"""
        )
        return True
    elif time_left.days < 30:
        logger.info("Only {} days remaining, will proceed with renewal for {}".format(time_left.days, site['CLOUDFRONT_ID']))
        return True
    else:
        logger.info("{} days remaining on cert, nothing to do for {}.".format(time_left.days, site['CLOUDFRONT_ID']))
        return False


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
    ssl_method = cf_config['DistributionConfig']['ViewerCertificate'].get('SSLSupportMethod', None)
    if ssl_method != 'sni-only':
        changed = True
        cf_config['DistributionConfig']['ViewerCertificate']['MinimumProtocolVersion'] = 'TLSv1'
        cf_config['DistributionConfig']['ViewerCertificate']['SSLSupportMethod'] = 'sni-only'

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
        if not cert_needs_renewal(site):
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
            logger.info("Can't get cert for {}, still waiting on domain authorizations".format(site['CLOUDFRONT_ID']))
            continue

        try:
            # Now that we're authorized to get certs for the domain(s), lets generate
            # a private key and a csr, then use them to get a certificate
            logger.info("Generate CSR and get cert for {}".format(site['CLOUDFRONT_ID']))
            pkey, csr = AcmeCert.generate_csr(cfg.CERT_BITS, site['DOMAINS'])
            cert, cert_chain = AcmeCert.get_cert(user, csr)
            # With our certificate in hand we can update the cloudfront distribution
            ret = cloudfront_configure_cert(site, cert, pkey, cert_chain)
            if ret:
                notify_email("Certificate issued",
                             "The certificate for {} has been successfully updated".format(site['CLOUDFRONT_ID']))
            else:
                notify_email("Error issuing cert",
                             "There was some sort of error configuring cloudfront with the certificate." +
                             "Please review the logs in cloudwatch." +
                             site['CLOUDFRONT_ID'])
        except Exception as e:
            logger.warning(e)

# Support running directly for testing
if __name__ == '__main__':
    lambda_handler(None, None)
