#!/usr/bin/env python
"""Lambda Lets-Encrypt Configuration/Setup Tool

This is a wizard that will help you configure the Lambda function to
automatically manage your SSL certifcates for CloudFront Distributions.

Usage:
  setup.py
  setup.py (-h | --help)
  setup.py --version

Options:
    -h --help   Show this screen
    --version   Show the version
"""
from __future__ import print_function
import json
import textwrap
import time
import zipfile
from docopt import docopt
from string import Template

from installer import sns, cloudfront, iam, s3, awslambda, elb, route53


class colors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    QUESTION = '\033[96m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def write_str(string):
    lines = textwrap.wrap(textwrap.dedent(string), 80)
    for line in lines:
        print(line)


def print_header(string):
    print()
    print(colors.OKGREEN, end='')
    write_str(string)
    print(colors.ENDC, end='')


def get_input(prompt, allow_empty=True):
    from sys import version_info
    py3 = version_info[0] > 2  # creates boolean value for test that Python major version > 2
    response = None
    while response is None or (not allow_empty and len(response) == 0):
        print(colors.QUESTION + "> " + prompt + colors.ENDC, end='')
        if py3:
            response = input()
        else:
            response = raw_input()
    return response


def get_yn(prompt, default=True):
    if default is True:
        prompt += "[Y/n]? "
        default = True
    else:
        prompt += "[y/N]? "
        default = False
    ret = get_input(prompt, allow_empty=True)
    if len(ret) == 0:
        return default
    if ret.lower() == "y" or ret.lower() == "yes":
        return True
    return False


def get_selection(prompt, options, prompt_after='Please select from the list above', allow_empty=False):
    if allow_empty:
        prompt_after += "(Empty for none)"
    prompt_after += ": "
    while True:
        print(prompt)
        for item in options:
            print('[{}] {}'.format(item['selector'], item['prompt']))
        print()
        choice = get_input(prompt_after, allow_empty=True)

        # Allow for empty things if desired
        if len(choice) == 0 and allow_empty:
            return None

        # find and return their choice
        for x in options:
            if choice == str(x['selector']):
                return x['return']
        print(colors.WARNING + 'Please enter a valid choice!' + colors.ENDC)


def choose_s3_bucket():
    bucket_list = s3.s3_list_buckets()
    options = []
    for i, bucket in enumerate(bucket_list):
        options.append({
            'selector': i,
            'prompt': bucket,
            'return': bucket
        })
    return get_selection("Select the S3 Bucket to use:", options, prompt_after="Which S3 Bucket?", allow_empty=False)


def wizard_elb(global_config):
    print_header("ELB Configuration")
    write_str("""\
        Now we'll detect your existing Elastic Load Balancers and allow you
        to configure them to use SSL. You must select the domain names
        you want on the certificate for each ELB.""")
    write_str("""\
        Note that only DNS validation(via Route53) is supported for ELBs""")
    print()

    global_config['elb_sites'] = []
    global_config['elb_domains'] = []

    # Get the list of all Cloudfront Distributions
    elb_list = elb.list_elbs()
    elb_list_opts = []
    for i, elb_name in enumerate(elb_list):
        elb_list_opts.append({
            'selector': i,
            'prompt': elb_name,
            'return': elb_name
        })

    route53_list = route53.list_zones()
    route53_list_opts = []
    for i, zone in enumerate(route53_list):
        route53_list_opts.append({
            'selector': i,
            'prompt': "{} - {}".format(zone['Name'], zone['Id']),
            'return': zone
        })

    while True:
        lb = get_selection("Choose an ELB to configure SSL for(Leave blank for none)", elb_list_opts, prompt_after="Which ELB?", allow_empty=True)
        if lb is None:
            break

        lb_port = get_input("What port number will this certificate be for(HTTPS is 443) [443]?", allow_empty=True)
        if len(lb_port) == 0:
            lb_port = 443

        domains = []
        while True:
            if len(domains) > 0:
                print("Already selected: {}".format(",".join(domains)))
            zone = get_selection("Choose a Route53 Zone that points to this load balancer: ", route53_list_opts, prompt_after="Which zone?", allow_empty=True)
            # stop when they don't enter anything
            if zone is None:
                break

            # Only allow adding each domain once
            if zone['Name'] in domains:
                continue
            domains.append(zone['Name'])
            global_config['elb_domains'].append({
                'DOMAIN': zone['Name'],
                'ROUTE53_ZONE_ID': zone['Id'],
                'VALIDATION_METHODS': ['dns-01']
            })

        site = {
            'ELB_NAME': lb,
            'ELB_PORT': lb_port,
            'DOMAINS': domains,
        }
        global_config['elb_sites'].append(site)


def wizard_cf(global_config):
    print_header("CloudFront Configuration")

    global_config['cf_sites'] = []
    global_config['cf_domains'] = []

    # Get the list of all Cloudfront Distributions
    cf_dist_list = cloudfront.list_distributions()
    cf_dist_opts = []
    for i, d in enumerate(cf_dist_list):
        cf_dist_opts.append({
            'selector': i,
            'prompt': "{} - {} ({}) ".format(d['Id'], d['Comment'], ", ".join(d['Aliases'])),
            'return': d
        })

    write_str("""\
        Now we'll detect your existing CloudFront Distributions and allow you
        to configure them to use SSL. Domain names will be automatically
        detected from the 'Aliases/CNAMEs' configuration section of each
        Distribution.""")
    print()
    write_str("""\
        You will configure each Distribution fully before being presented with
        the list of Distributions again. You can configure as many Distributions
        as you like.""")
    while True:
        print()
        dist = get_selection("Select a CloudFront Distribution to configure with Lets-Encrypt(leave blank to finish)", cf_dist_opts, prompt_after="Which CloudFront Distribution?", allow_empty=True)
        if dist is None:
            break

        cnames = dist['Aliases']
        write_str("The following domain names exist for the selected CloudFront Distribution:")
        write_str("    " + ", ".join(cnames))
        write_str("Each domain in this list will be validated with Lets-Encrypt and added to the certificate assigned to this Distribution.")
        print()
        for dns_name in cnames:
            domain = {
                'DOMAIN': dns_name,
                'VALIDATION_METHODS': []
            }
            print("Choose validation methods for the domain '{}'".format(dns_name))
            route53_id = route53.get_zone_id(dns_name)
            if route53_id:
                write_str(colors.OKGREEN + "Route53 zone detected!" + colors.ENDC)
                validate_via_dns = get_yn("Validate using DNS", default=False)
                if validate_via_dns:
                    domain['ROUTE53_ZONE_ID'] = route53_id
                    domain['VALIDATION_METHODS'].append('dns-01')
            else:
                write_str(colors.WARNING + "No Route53 zone detected, DNS validation not possible." + colors.ENDC)

            validate_via_http = get_yn("Validate using HTTP", default=True)
            if validate_via_http:
                domain['CLOUDFRONT_ID'] = dist['Id']
                domain['VALIDATION_METHODS'].append('http-01')

            global_config['cf_domains'].append(domain)
        site = {
            'CLOUDFRONT_ID': dist['Id'],
            'DOMAINS': cnames
        }
        global_config['cf_sites'].append(site)


def wizard_sns(global_config):
    sns_email = None

    print_header("Notifications")
    write_str("""\
        The lambda function can send notifications when a certificate is issued,
        errors occur, or other things that may need your attention.
        Notifications are optional.""")

    use_sns = True
    sns_email = get_input("Enter the email address for notifications(blank to disable): ", allow_empty=True)
    if len(sns_email) == 0:
        use_sns = False

    global_config['use_sns'] = use_sns
    global_config['sns_email'] = sns_email


def wizard_s3_cfg_bucket(global_config):
    print_header("S3 Configuration Bucket")
    write_str('An S3 Bucket is required to store configuration. If you already have a bucket you want to use for this choose no and select it from the list. Otherwise let the wizard create one for you.')
    create_s3_cfg_bucket = get_yn("Create a bucket for configuration", True)

    if create_s3_cfg_bucket:
        s3_cfg_bucket = "lambda-letsencrypt-config-{}".format(global_config['ts'])
    else:
        s3_cfg_bucket = choose_s3_bucket()

    global_config['create_s3_cfg_bucket'] = create_s3_cfg_bucket
    global_config['s3_cfg_bucket'] = s3_cfg_bucket


def wizard_iam(global_config):
    print_header("IAM Configuration")
    write_str("An IAM role must be created for this lambda function giving it access to CloudFront, Route53, S3, SNS(notifications), IAM(certificates), and CloudWatch(logs/alarms).")
    print()
    write_str("If you do not let the wizard create this role you will be asked to select an existing role to use.")
    create_iam_role = get_yn("Do you want to automatically create this role", True)
    if not create_iam_role:
        role_list = iam.list_roles()
        options = []
        for i, role in enumerate(role_list):
            options.append({
                'selector': i,
                'prompt': role,
                'return': role
            })
        iam_role_name = get_selection("Select the IAM Role:", options, prompt_after="Which IAM Role?", allow_empty=False)
    else:
        iam_role_name = "lambda-letsencrypt"

    global_config['create_iam_role'] = create_iam_role
    global_config['iam_role_name'] = iam_role_name


def wizard_challenges(global_config):
    create_s3_challenge_bucket = False
    s3_challenge_bucket = None

    print_header("Lets-Encrypt Challenge Validation Settings")
    write_str("""This tool will handle validation of your domains automatically. There are two possible validation methods: HTTP and DNS.""")
    print()
    write_str("HTTP validation is only available for CloudFront sites. It requires an S3 bucket to store the challenge responses in. This bucket needs to be publicly accessible. Your CloudFront Distribution(s) will be reconfigured to use this bucket as an origin for challenge responses.")
    write_str("If you do not configure a bucket for this you will only be able to use DNS validation.")
    print()
    write_str("DNS validation requires your domain to be managed with Route53. This validation method is always available and requires no additional configuration.")
    write_str(colors.WARNING + "Note: DNS validation is currently only supported by the staging server." + colors.ENDC)
    print()
    write_str("Each domain you want to manage can be configured to validate using either of these methods.")
    print()

    use_http_challenges = get_yn("Do you want to configure HTTP validation", True)
    if use_http_challenges:
        create_s3_challenge_bucket = get_yn("Do you want to create a bucket for these challenges(Choose No to select an existing bucket)", True)
        if create_s3_challenge_bucket:
            s3_challenge_bucket = "lambda-letsencrypt-challenges-{}".format(global_config['ts'])
        else:
            s3_challenge_bucket = choose_s3_bucket()
    else:
        # only dns challenge support is available
        pass

    global_config['use_http_challenges'] = use_http_challenges
    global_config['create_s3_challenge_bucket'] = create_s3_challenge_bucket
    global_config['s3_challenge_bucket'] = s3_challenge_bucket


def wizard_summary(global_config):
    gc = global_config

    print_header("**Summary**")
    print("Notification Email:                              {}".format(gc['sns_email'] or "(notifications disabled)"))

    print("S3 Config Bucket:                                {}".format(gc['s3_cfg_bucket']), end="")
    if (gc['create_s3_cfg_bucket']):
        print(" (to be created)")
    else:
        print(" (existing)")

    if gc['create_iam_role']:
        print("IAM Role Name:                                   {} (to be created)".format(gc['iam_role_name']))
    else:
        print("IAM Role Name:                                   {} (existing)".format(gc['iam_role_name']))

    print("Support HTTP Challenges:                         {}".format(gc['use_http_challenges']))
    if gc['use_http_challenges']:
        print("S3 HTTP Challenge Bucket:                        {}".format(gc['s3_challenge_bucket']), end="")
        if (gc['create_s3_challenge_bucket']):
            print(" (to be created)")
        else:
            print(" (existing)")

    print("Domains To Manage With Lets-Encrypt")
    for d in gc['cf_domains']:
        print("    {} - [{}]".format(d['DOMAIN'], ",".join(d['VALIDATION_METHODS'])))
    for d in gc['elb_domains']:
        print("    {} - [{}]".format(d['DOMAIN'], ",".join(d['VALIDATION_METHODS'])))

    print("CloudFront Distributions To Manage:")
    for cf in gc['cf_sites']:
        print("    {} - [{}]".format(cf['CLOUDFRONT_ID'], ",".join(cf['DOMAINS'])))

    print("Elastic Load Balancers to Manage:")
    for lb in gc['elb_sites']:
        print("    {}:{} - [{}]".format(lb['ELB_NAME'], lb['ELB_PORT'], ",".join(lb['DOMAINS'])))


def wizard_save_config(global_config):
    print_header("Making Requested Changes")
    templatevars = {}
    with open('config.py.dist', 'r') as template:
        configfile = Template(template.read())

    templatevars['SNS_ARN'] = None
    templatevars['NOTIFY_EMAIL'] = None

    # Configure SNS if appropriate
    sns_arn = None
    if len(global_config['sns_email']) > 0:
        # Create SNS Topic if necessary
        print("Creating SNS Topic for Notifications ", end='')
        sns_arn = sns.get_or_create_topic(global_config['sns_email'])
        if sns_arn is False or sns_arn is None:
            print(colors.FAIL + u'\u2717' + colors.ENDC)
        else:
            print(colors.OKGREEN + u'\u2713' + colors.ENDC)
            templatevars['SNS_ARN'] = sns_arn
            templatevars['NOTIFY_EMAIL'] = global_config['sns_email']

    # create config bucket if necessary
    if global_config['create_s3_cfg_bucket']:
        print("Creating S3 Configuration Bucket ", end='')
        s3.create_bucket(global_config['s3_cfg_bucket'])
        print(colors.OKGREEN + u'\u2713' + colors.ENDC)

    # create challenge bucket if necessary(needs to be configured as static website)
    if global_config['create_s3_challenge_bucket']:
        print("Creating S3 Challenge Bucket ", end='')
        s3.create_web_bucket(global_config['s3_challenge_bucket'])
        print(colors.OKGREEN + u'\u2713' + colors.ENDC)

    # create IAM role if required
    if global_config['create_iam_role']:
        global_config['iam_role_name'] = 'lambda-letsencrypt-test-role'
        policy_document = iam.generate_policy_document(
            s3buckets=[
                global_config['s3_cfg_bucket'],
                global_config['s3_challenge_bucket']
            ],
            snstopicarn=sns_arn
        )
        iam_arn = iam.configure(global_config['iam_role_name'], policy_document)

    templatevars['S3_CONFIG_BUCKET'] = global_config['s3_cfg_bucket']
    templatevars['S3_CHALLENGE_BUCKET'] = global_config['s3_challenge_bucket']

    domains = global_config['cf_domains'] + global_config['elb_domains']
    sites = global_config['cf_sites'] + global_config['elb_sites']
    templatevars['DOMAINS'] = json.dumps(domains, indent=4)
    templatevars['SITES'] = json.dumps(sites, indent=4)

    # write out the config file
    config = configfile.substitute(templatevars)
    with open("config-wizard.py", 'w') as configfinal:
        print("Writing Configuration File ", end='')
        configfinal.write(config)
        print(colors.OKGREEN + u'\u2713' + colors.ENDC)

    print("Creating Zip File To Upload To Lambda")
    archive_success = True
    archive = zipfile.ZipFile('lambda-letsencrypt-dist.zip', mode='w')
    try:
        for f in ['lambda_function.py', 'simple_acme.py']:
            print("    Adding '{}'".format(f))
            archive.write(f)
        print("    Adding 'config.py'")
        archive.write('config-wizard.py', 'config.py')
    except Exception as e:
        print(colors.FAIL + 'Zip File Creation Failed' + colors.ENDC)
        print(e)
        archive_success = False
    finally:
        print('Zip File Created Successfully')
        archive.close()

    # can't continue if this failed
    if not archive_success:
        return

    print("Configuring Lambda Function:")
    iam_arn = iam.get_arn(global_config['iam_role_name'])
    print("    IAM ARN: {}".format(iam_arn))
    print("    Uploading Function ", end='')
    if awslambda.create_function("lambda-letsencrypt", iam_arn, 'lambda-letsencrypt-dist.zip'):
        print(colors.OKGREEN + u'\u2713' + colors.ENDC)
    else:
        print(colors.FAIL + u'\u2717' + colors.ENDC)
        return

    print_header("Schedule Lambda Function")
    write_str("I've done all I can for you now, there's one last step you have to take manually in order to schedule your lambda function to run once a day.")
    write_str("Log into your aws console and go to this page:")
    lambda_event_url = "https://console.aws.amazon.com/lambda/home#/functions/lambda-letsencrypt?tab=eventSources"
    print(colors.OKBLUE + lambda_event_url + colors.ENDC)
    print()
    write_str('Click on "Add event source". From the dropdown, choose "Scheduled Event". Enter the following:')
    write_str("Name:                 'daily - rate(1 day)'")
    write_str("Description:          'Run every day'")
    write_str("Schedule Expression:  'rate(1 day)'")
    print()
    write_str("Choose to 'Enable Now', then click 'Submit'")

    print_header("Testing")
    write_str("You may want to test this before you set it to be recurring. Click on the 'Test' button in the AWS Console for the lambda-letsencrypt function. The data you provide to this function does not matter. Make sure to review the logs after it finishes and check for anything out of the ordinary.")
    print()
    write_str("It will take at least 2 runs before your certificates are issued, maybe 3 depending on how fast cloudfront responds. This is because it needs one try to configure cloudfront, one to submit the challenge and have it verified, and one final run to issue the certificate and configure the cloudfront distribution")


def wizard(global_config):
    ts = int(time.time())
    ts = 1000
    global_config['ts'] = ts
    print_header("Lambda Lets-Encrypt Wizard")
    write_str("""\
        This wizard will guide you through the process of setting up your existing
        CloudFront Distributions to use SSL certificates provided by Lets-Encrypt
        and automatically issued/maintained by an AWS Lambda function.

        These certificates are free of charge, and valid for 90 days. This wizard
        will also set up a Lambda function that is responsible for issuing and
        renewing these certificates automatically as they near their expiration
        date.

        The cost of the AWS services used to make this work are typically less
        than a penny per month. For full pricing details please refer to the
        docs.
    """)

    print()
    print(colors.WARNING + "WARNING: ")
    write_str("""\
        Manual configuration is required at this time to configure the Lambda
        function to run on a daily basis to keep your certificate updated. If
        you do not follow the steps provided at the end of this wizard your
        Lambda function will *NOT* run.
    """)
    print(colors.ENDC)

    wizard_sns(global_config)
    wizard_iam(global_config)
    wizard_s3_cfg_bucket(global_config)
    wizard_challenges(global_config)
    wizard_cf(global_config)
    wizard_elb(global_config)

    cfg_menu = []
    cfg_menu.append({'selector': 1, 'prompt': 'SNS', 'return': wizard_sns})
    cfg_menu.append({'selector': 2, 'prompt': 'IAM', 'return': wizard_iam})
    cfg_menu.append({'selector': 3, 'prompt': 'S3 Config', 'return': wizard_s3_cfg_bucket})
    cfg_menu.append({'selector': 4, 'prompt': 'Challenges', 'return': wizard_challenges})
    cfg_menu.append({'selector': 5, 'prompt': 'CloudFront', 'return': wizard_cf})
    cfg_menu.append({'selector': 6, 'prompt': 'Elastic Load Balancers', 'return': wizard_cf})
    cfg_menu.append({'selector': 9, 'prompt': 'Done', 'return': None})

    finished = False
    while not finished:
        wizard_summary(global_config)
        finished = get_yn("Are these settings correct", True)
        if not finished:
            selection = get_selection("Which section do you want to change", cfg_menu, prompt_after="Which section to modify?", allow_empty=False)
            if selection:
                selection(global_config)

    wizard_save_config(global_config)


if __name__ == "__main__":
    args = docopt(__doc__, version='Lambda Lets-Encrypt 1.0')
    global_config = {}
    wizard(global_config)
