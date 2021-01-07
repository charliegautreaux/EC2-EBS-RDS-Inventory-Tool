import lib_calipers as cal
import json
import boto3
from datetime import datetime

nl = '\n'


def run(aws_account, analysis_id, region, count_blocks):
    print(f'Reporting on the following AWS Regions {region}{nl}')

    cb = count_blocks

    '''initialize dictionaries'''
    ec2_master = []
    ebs_vols_master = []
    ebs_snaps_master = []
    rds_master = []

    'Regional iterative with connection to relevent service'
    'Gathers regional data and append to global/master dictionaries'

    '''********  EC2 / EBS  **********'''

    '''Create EC2/ EBS Connection Objects'''
    ec2_conn = cal.connect_service(region, 'ec2')
    ebs_conn = cal.connect_service(region, 'ebs')

    '''fetch data + build ec2 report dictionary'''
    for i in (cal.ec2_report(region, ec2_conn)):
        ec2_master.append(i)

    try:
        '''fetch data for EBS report dictionaries'''
        in_use_ebs_list, in_use_ebs_response = cal.get_ebs_vols(
            region, ec2_conn, 'in-use')
        avail_ebs_list, avail_ebs_response = cal.get_ebs_vols(
            region, ec2_conn, 'available')
        in_use_ebs_snap_reponse = cal.get_ebs_snapshots(
            region, ec2_conn, in_use_ebs_list)
        avail_ebs_snap_reponse = cal.get_ebs_snapshots(
            region, ec2_conn, avail_ebs_list)
    except Exception as e:
        print(f'failed to gather EBS data for {region}:{e}')
        pass

    '''feed in data to generate EBS volume report dictionaries'''
    try:
        in_use_dict = cal.ebs_vols_report(
            region, ec2_conn, ebs_conn, in_use_ebs_response,
            in_use_ebs_snap_reponse, True, cb)
        avail_dict = cal.ebs_vols_report(
            region, ec2_conn, ebs_conn, avail_ebs_response,
            avail_ebs_snap_reponse, False, cb)
        ebs_vols_master += in_use_dict
        ebs_vols_master += avail_dict
    except Exception as e:
        print(f'failed to process EBS data for {region}:{e}')
        pass

    '''feed in data to generate EBS Snapshot report Dictionaries'''
    try:
        all_vols = avail_ebs_list + in_use_ebs_list
        all_ebs_backed_snaps = (in_use_ebs_snap_reponse +
                                avail_ebs_snap_reponse)
        orphan_ebs_snaps = cal.get_orphan_ebs_snaps(ec2_conn, all_vols)
        ebs_snaps_master += (cal.ebs_snap_report(
            region, ec2_conn, ebs_conn, all_ebs_backed_snaps, True, cb))
        ebs_snaps_master += cal.ebs_snap_report(
            region, ec2_conn, ebs_conn, orphan_ebs_snaps, False, cb)
    except Exception as e:
        print(f'failed to process EBS snapshot data for {region}:{e}')
        pass

    '''RDS'''
    try:
        rds_conn = cal.connect_service(region, 'rds')
        dbi_response = cal.get_rds(region, rds_conn, 'instance')
        dbc_response = cal.get_rds(region, rds_conn, 'cluster')
        rds_master += (cal.rds_inst_report(
            region, rds_conn, dbi_response))
        rds_master += (cal.rds_clust_report(
            region, rds_conn, dbc_response))
    except Exception as e:
        print(f'failed to gather RDS data for {region}:{e}')

    'create timestamp'
    now = datetime.utcnow()
    timestamp = now.strftime("%Y-%m-%d %H:%M")

    'Inject customer account info into records'
    all_dicts = [ec2_master, ebs_vols_master, ebs_snaps_master, rds_master]

    for items in all_dicts:
        for _ in range(len(items)):
            items[_]['AWS Account'] = aws_account
            items[_]['Analysis_ID'] = analysis_id
            items[_]['Record Date'] = timestamp
            items[_]['Region'] = region

    return all_dicts


def convertJSON_S3(target_bucket, target_file_name, input_dict):
    if len(input_dict) > 0:
        body = json.dumps(input_dict)
        s3 = boto3.client('s3')
        print("Check s3 put", s3.put_object(Bucket=target_bucket,
                                            Key=target_file_name,
                                            Body=body))


def handler(event, context):
    'set timestamp'
    now = datetime.utcnow()
    timestamp = now.strftime("%Y-%m-%d_%H:%M")

    'import/set variables'
    region = event['region']
    customer_name = event['customer']
    bucket = event['s3']
    count_blocks = event['count_blocks']
    analysis_id = f'{customer_name}-{timestamp}'

    'configure session information'
    session = boto3.Session(aws_access_key_id=event['access_key'],
                            aws_secret_access_key=event['secret_key'],
                            aws_session_token=event['session_token'])

    'fetch AWS Account number'
    crossClient = session.client('sts')
    aws_account = crossClient.get_caller_identity().get('Account')

    'collect account data'
    ec2, ebs, ebs_snaps, rds = run(
        aws_account, analysis_id, region, count_blocks)

    'convert and send to local s3'
    convertJSON_S3(bucket, f'{analysis_id}-{aws_account}-ec2.json', ec2)
    convertJSON_S3(bucket, f'{analysis_id}-{aws_account}-ebs.json', ebs)
    convertJSON_S3(
        bucket, f'{analysis_id}-{aws_account}-ebs_snaps.json', ebs_snaps)
    convertJSON_S3(bucket, f'{analysis_id}-{aws_account}-rds.json', rds)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "hello world",
        }),
    }
