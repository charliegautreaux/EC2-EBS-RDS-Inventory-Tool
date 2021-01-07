import boto3
import datetime

nl = "\n"


def ec2_report(region, ec2_conn):
    '''initialize variables'''
    custom_ec2_dict = []
    response = []
    response_dict = []
    ec2_vols = []
    vols_dict = []
    tags = None

    try:
        '''fetch running and stopped ec2 instances with paginator'''
        print(f'{nl}Fetching EC2 Data from {region}...')

        pag = ec2_conn.get_paginator('describe_instances')
        for page in pag.paginate(Filters=[
                {
                    'Name': 'instance-state-name',
                    'Values': ['running', 'stopped']
                },

        ], PaginationConfig={
                'PageSize': 150
        }
        ):
            for i in page['Reservations']:
                response.append(i)
    except Exception as e:
        print(f'Failed to fetch EC2 Instances {e}')

    '''this line can probs be removed by adding [instances] to array above'''
    for d in range(len(response)):
        for i in range(len(response[d]['Instances'])):
            response_dict.append(response[d]['Instances'][i])

    print(f'{nl}Found {len(response_dict)} EC2 instances {region}')

    try:
        '''fetch all volumes associated with EC2 Instances'''
        ec2_vols = []
        for i in range(len(response_dict)):
            for v in range(len(response_dict[i]['BlockDeviceMappings'])):
                ec2_vols.append(response_dict[i]['BlockDeviceMappings'][v]
                                ['Ebs']['VolumeId'])

        '''fetch detailed volume info for associated EC2 instances'''
        p = Paginator(ec2_vols, 150)
        for i in p:
            response = ec2_conn.describe_volumes(Filters=[
                {
                    'Name': 'volume-id',
                    'Values': i,
                }
            ])['Volumes']
            for i in response:
                vols_dict.append(i)
    except Exception as e:
        print(f'Failed to fetch volumes assocated with EC2 instances {e}')

    try:
        '''iterate through regions appending data to datastructure'''
        for i in range(len(response_dict)):
            '''store volume IDs in local variable for loop'''
            vols = []
            tags = None
            for v in range(len(response_dict[i]['BlockDeviceMappings'])):
                vols.append(response_dict[i]['BlockDeviceMappings'][v]['Ebs']
                            ['VolumeId'])

            '''add up vol sizes'''
            ebs_agg = 0
            for v in vols:
                for d in range(len(vols_dict)):
                    if v == vols_dict[d]['VolumeId']:
                        ebs_agg = ebs_agg + vols_dict[d]['Size']

            '''try to get tags'''
            try:
                tags = tag_parser(response_dict[i]['Tags'])
            except Exception:
                tags = None
                pass

            '''write ec2 data to data structure'''
            custom_ec2_dict.append({
                'Record-Type': 'EC2 Instance',
                'InstanceId': response_dict[i]['InstanceId'],
                'Type': response_dict[i]['InstanceType'],
                'Power-State': response_dict[i]['State']['Name'],
                'Total EBS Provisioned (GB)': ebs_agg,
                'Attached-Volumes': str(vols),
                'Tag': 'All_Records'
            })

            if tags:
                for _ in range(len(tags)):
                    custom_ec2_dict.append({
                        'Record-Type': 'EC2 Instance',
                        'InstanceId': response_dict[i]['InstanceId'],
                        'Type': response_dict[i]['InstanceType'],
                        'Power-State': response_dict[i]['State']['Name'],
                        'Total EBS Provisioned (GB)': ebs_agg,
                        'Attached-Volumes': str(vols),
                        'Tag': tags[_]
                    })

    except Exception as e:
        print(f'No EC2 Instances found in {region}:{nl}{e}')

    return custom_ec2_dict


def ebs_vols_report(region, ec2_conn, ebs_conn,
                    vols_response, snap_list, in_use, cb):
    custom_ebs_dict = []
    tags = None

    '''create snaptime dict for active snaps'''
    snaptime_dict = catalog_snaps(
        snap_list, 'VolumeId', 'StartTime')

    '''parse active ebs item level stats + dump to custom dictionary'''
    rbchck = None
    try:
        for i in range(len(vols_response)):
            snap_calendar = count_snaps(
                snaptime_dict, vols_response, i, 'VolumeId')

            '''encrypted true/false'''
            encryption = ''
            if vols_response[i]['Encrypted']:
                encryption = 'Yes'
            else:
                encryption = 'No'

            '''collect tag info'''
            try:
                tags = tag_parser(vols_response[i]['Tags'])
            except Exception:
                pass

            '''determine true size of volume'''
            if not rbchck:
                print('\nCalculating consumed size of your In-Use EBS Vols')
                print('This may take up to 5 minutes per 100 Volumes\n')
                rbchck = True
            vol_id = vols_response[i]['VolumeId']
            consumed_blocks = vol_sizer(
                custom_ebs_dict, vol_id, ec2_conn, ebs_conn, cb)

            '''write out data to dictionary'''
            custom_ebs_dict.append({
                    'Record-Type': 'EBS Volume',
                    'In-use': in_use,
                    'VolumeId': vols_response[i]['VolumeId'],
                    'Size (GB)': vols_response[i]['Size'],
                    'Consumed Size (GB)': consumed_blocks,
                    'Disk Type': vols_response[i]['VolumeType'],
                    'Encrypted?': encryption,
                    'Snaps -24 Hours': snap_calendar['last_24'],
                    'Snaps -7 Days': snap_calendar['last_7'],
                    'Snaps -30 Days': snap_calendar['last_30'],
                    'Snaps 30-365 Days': snap_calendar['_30to365'],
                    'Snaps older than 1yr': snap_calendar['older'],
                    'Total Snaps': snap_calendar['all_snaps'],
                    'Tag': 'All_Records'
                })

            for _ in range(len(tags)):
                custom_ebs_dict.append({
                    'Record-Type': 'EBS Volume',
                    'In-use': in_use,
                    'VolumeId': vols_response[i]['VolumeId'],
                    'Size (GB)': vols_response[i]['Size'],
                    'Consumed Size (GB)': consumed_blocks,
                    'Disk Type': vols_response[i]['VolumeType'],
                    'Encrypted?': encryption,
                    'Snaps -24 Hours': snap_calendar['last_24'],
                    'Snaps -7 Days': snap_calendar['last_7'],
                    'Snaps -30 Days': snap_calendar['last_30'],
                    'Snaps 30-365 Days': snap_calendar['_30to365'],
                    'Snaps older than 1yr': snap_calendar['older'],
                    'Total Snaps': snap_calendar['all_snaps'],
                    'Tag': tags[_]
                })

    except Exception as e:
        print(f'Failed to  write non-orphan ebs data to dict{nl}{e}')

    return custom_ebs_dict


def ebs_snap_report(region, ec2_conn, ebs_conn, snap_response, backed, cb):
    ebs_snap_dict = []
    tags = None

    try:
        for i in range(len(snap_response)):
            '''check if snap is older than 60 days'''
            now = datetime.datetime.utcnow()
            snaptime = snap_response[i]['StartTime']
            snaptime = snaptime.replace(tzinfo=None)

            if snaptime <= (now - datetime.timedelta(days=60)):
                age = True
            else:
                age = False

            '''collect tag info'''
            try:
                tags = tag_parser(snap_response[i]['Tags'])
            except Exception:
                tags = None
                pass

            '''break up date time to date + time of day'''
            snapdate = snaptime.strftime("%m/%d/%Y")
            snaphours = snaptime.strftime("%H:%M")

            '''calculate snapshot size'''
            snap_id = snap_response[i]['SnapshotId']
            vol_id = snap_response[i]['VolumeId']
            snap_size = snap_sizer(ec2_conn, ebs_conn, ebs_snap_dict,
                                   vol_id, snap_id, cb)

            '''handle missing volume IDs (due to copied volumes)'''
            if snap_response[i]['VolumeId'] == 'vol-ffffffff':
                snap_size = None

            '''write out custom dictionary for orphan EBS snapshots'''
            ebs_snap_dict.append({
                    'Record-Type': 'EBS Snapshot',
                    'EBS Backed': backed,
                    'SnapshotId': snap_response[i]['SnapshotId'],
                    'Source Vol ID': snap_response[i]['VolumeId'],
                    'Source Vol Size (GB)': snap_response[i]['VolumeSize'],
                    'Snapshot Size on S3 (GB)': snap_size,
                    'Encrypted?': snap_response[i]['Encrypted'],
                    'Snap Date': snapdate,
                    'Snap Time': snaphours,
                    '60+ Days Old': age,
                    'Tag': 'All_Records'
                })

            for _ in range(len(tags)):
                ebs_snap_dict.append({
                    'Record-Type': 'EBS Snapshot',
                    'EBS Backed': backed,
                    'SnapshotId': snap_response[i]['SnapshotId'],
                    'Source Vol ID': snap_response[i]['VolumeId'],
                    'Source Vol Size (GB)': snap_response[i]['VolumeSize'],
                    'Snapshot Size on S3 (GB)': snap_size,
                    'Encrypted?': snap_response[i]['Encrypted'],
                    'Snap Date': snapdate,
                    'Snap Time': snaphours,
                    '60+ Days Old': age,
                    'Tag': tags[_]
                })

    except Exception as e:
        print(f'{nl}Error locating Orphan EBS Snaps from {region}:{nl}{e}')
    return ebs_snap_dict


def rds_inst_report(region, rds_conn, flat_dbi_response):
    custom_rds_inst_dict = []
    rds_instance_ids = []
    rds_db_snaps = []
    describe_db_snaps_response = []
    tags = None

    try:
        '''create list of rds instance ids'''
        for r in range(len(flat_dbi_response)):
            if ((flat_dbi_response[r]['Engine'] == 'aurora-postgresql'
                 or flat_dbi_response[r]['Engine'] == 'aurora'
                 or flat_dbi_response[r]['Engine'] == 'aurora-mysql')):
                pass
            else:
                rds_instance_ids.append(
                    flat_dbi_response[r]['DBInstanceIdentifier'])

    except Exception as e:
        print(f'failed to generate list of aurora instances {e}')

    '''read in all rds instance snapshots'''
    try:
        for i in rds_instance_ids:
            describe_db_snaps_response = rds_conn.describe_db_snapshots(
                MaxRecords=100,
                DBInstanceIdentifier=i)['DBSnapshots']
            for d in describe_db_snaps_response:
                rds_db_snaps.append(d)

    except Exception as e:
        print(f'{nl}Error locating RDS instance Snaps from {region}:{nl}{e}')

    '''parse snapshot times into dictionary'''
    snaptime_dict = catalog_snaps(
        rds_db_snaps, 'DBInstanceIdentifier', 'SnapshotCreateTime')

    '''define addtional variables + write selected data to RDS
    instance dictionary'''
    for i in range(len(flat_dbi_response)):
        snap_calendar = count_snaps(
            snaptime_dict, flat_dbi_response, i,
            'DBInstanceIdentifier')

        dbsize = None
        engine = flat_dbi_response[i]['Engine']
        engine_version = flat_dbi_response[i]['EngineVersion']

        '''dougs version checking algo'''
        is_granular_backup_supported, needs_internal_upgrade \
            = analyze_engine_info(engine, engine_version, "")

        try:
            if (engine == 'aurora-postgresql' or
                engine == 'aurora' or
                    engine == 'aurora-mysql'):
                dbsize = None
            else:
                dbsize = flat_dbi_response[i]['AllocatedStorage']

        except Exception as e:
            print('''\nError retreiving aurora snapshot for ''' +
                  str(flat_dbi_response[i]['DBInstanceIdentifier']) +
                  '\n' + str(e))

        '''perform aurora name translations'''
        if engine == 'aurora':
            engine = 'aurora-mysql'

        '''lookup DB instance tags'''
        try:
            tagjson = list_rds_tags(rds_conn,
                                    flat_dbi_response[i]['DBInstanceArn'])
            tags = tag_parser(tagjson)
        except Exception:
            tags = None
            pass

        'write out values to dictionary'
        custom_rds_inst_dict.append({
                'Record-Type': 'RDS Instance',
                'DB Identifier': flat_dbi_response[i]['DBInstanceIdentifier'],
                'AllocatedStorage (GB)': dbsize,
                'Status': flat_dbi_response[i]['DBInstanceStatus'],
                'Retention Period': flat_dbi_response[i]['BackupRetentionPeriod'],
                'Engine': engine,
                'EngineVersion': engine_version,
                'EngineMode': '',
                'IsGranularBackupSupported': str(is_granular_backup_supported),
                'NeedsInternalUpgrade': str(needs_internal_upgrade),
                'MultiAZ': flat_dbi_response[i]['MultiAZ'],
                'Instance Type': flat_dbi_response[i]['DBInstanceClass'],
                'CrossAccountClone': '',
                'Snaps -24 Hours': snap_calendar['last_24'],
                'Snaps -7 Days': snap_calendar['last_7'],
                'Snaps -30 Days': snap_calendar['last_30'],
                'Snaps 30-365 Days': snap_calendar['_30to365'],
                'Snaps older than 1yr': snap_calendar['older'],
                'Total Snaps': snap_calendar['all_snaps'],
                'Tag': 'All_Records'
            })

        for _ in range(len(tags)):
            custom_rds_inst_dict.append({
                'Record-Type': 'RDS Instance',
                'DB Identifier': flat_dbi_response[i]['DBInstanceIdentifier'],
                'AllocatedStorage (GB)': dbsize,
                'Status': flat_dbi_response[i]['DBInstanceStatus'],
                'Retention Period': flat_dbi_response[i]['BackupRetentionPeriod'],
                'Engine': engine,
                'EngineVersion': engine_version,
                'EngineMode': '',
                'IsGranularBackupSupported': str(is_granular_backup_supported),
                'NeedsInternalUpgrade': str(needs_internal_upgrade),
                'MultiAZ': flat_dbi_response[i]['MultiAZ'],
                'Instance Type': flat_dbi_response[i]['DBInstanceClass'],
                'CrossAccountClone': '',
                'Snaps -24 Hours': snap_calendar['last_24'],
                'Snaps -7 Days': snap_calendar['last_7'],
                'Snaps -30 Days': snap_calendar['last_30'],
                'Snaps 30-365 Days': snap_calendar['_30to365'],
                'Snaps older than 1yr': snap_calendar['older'],
                'Total Snaps': snap_calendar['all_snaps'],
                'Tag': tags[_]
            })

    return custom_rds_inst_dict


def rds_clust_report(region, rds_conn, flat_dbc_response):
    custom_rds_clusters_dict = []
    rds_cluster_ids = []
    rds_cluster_snaps = []
    snap_calendar = []
    snaptime_dict = []
    tags = None

    '''read in all rds cluster snapshots'''
    try:
        for i in rds_cluster_ids:
            describe_db_snaps_response = get_rds_clustersnaps(rds_conn, i)
            for d in describe_db_snaps_response:
                rds_cluster_snaps.append(d)

    except Exception as e:
        print(f'{nl}Error locating rds instance Snaps from {region}: {e}')

    '''parse snapshot times into dictionary'''
    snaptime_dict = catalog_snaps(
        rds_cluster_snaps, 'DBClusterIdentifier', 'SnapshotCreateTime')

    '''write RDS data to data structure'''
    for i in range(len(flat_dbc_response)):
        snap_calendar = count_snaps(snaptime_dict, flat_dbc_response, i,
                                    'DBClusterIdentifier')

        allocatedGB = None
        engine = flat_dbc_response[i]['Engine']
        engine_version = flat_dbc_response[i]['EngineVersion']
        engine_mode = flat_dbc_response[i]['EngineMode']

        is_granular_backup_supported, needs_internal_upgrade \
            = analyze_engine_info(engine, engine_version, engine_mode)
        try:
            allocatedGB = get_aurora_allocated(
                rds_conn, flat_dbc_response[i]['DBClusterIdentifier'])
        except Exception as e:
            print(f'''failed to retreived DB size for
            {flat_dbc_response[i]['DBClusterIdentifier']}{nl} {e}''')

        '''perform aurora name translations'''
        if engine == 'aurora':
            engine = 'aurora-mysql'

        '''lookup db Tags'''
        try:
            tagjson = list_rds_tags(rds_conn, flat_dbc_response[i]['DBClusterArn'])
            tags = tag_parser(tagjson)
        except Exception:
            tags = None
            pass

        'write out values to dictionary'
        custom_rds_clusters_dict.append({
                'Record-Type': 'RDS Cluster',
                'DB Identifier': flat_dbc_response[i]['DBClusterIdentifier'],
                'AllocatedStorage (GB)': allocatedGB,
                'Status': flat_dbc_response[i]['Status'],
                'Retention Period': flat_dbc_response[i]['BackupRetentionPeriod'],
                'Engine': engine,
                'EngineVersion': engine_version,
                'EngineMode': engine_mode,
                'IsGranularBackupSupported': str(is_granular_backup_supported),
                'NeedsInternalUpgrade': str(needs_internal_upgrade),
                'MultiAZ': flat_dbc_response[i]['MultiAZ'],
                'Instance Type': '',
                'CrossAccountClone': flat_dbc_response[i]['CrossAccountClone'],
                'Snaps -24 Hours': snap_calendar['last_24'],
                'Snaps -7 Days': snap_calendar['last_7'],
                'Snaps -30 Days': snap_calendar['last_30'],
                'Snaps 30-365 Days': snap_calendar['_30to365'],
                'Snaps older than 1yr': snap_calendar['older'],
                'Total Snaps': snap_calendar['all_snaps'],
                'Tag': 'All_Records'
            })

        for _ in range(len(tags)):
            custom_rds_clusters_dict.append({
                'Record-Type': 'RDS Cluster',
                'DB Identifier': flat_dbc_response[i]['DBClusterIdentifier'],
                'AllocatedStorage (GB)': allocatedGB,
                'Status': flat_dbc_response[i]['Status'],
                'Retention Period': flat_dbc_response[i]['BackupRetentionPeriod'],
                'Engine': engine,
                'EngineVersion': engine_version,
                'EngineMode': engine_mode,
                'IsGranularBackupSupported': str(is_granular_backup_supported),
                'NeedsInternalUpgrade': str(needs_internal_upgrade),
                'MultiAZ': flat_dbc_response[i]['MultiAZ'],
                'Instance Type': '',
                'CrossAccountClone': flat_dbc_response[i]['CrossAccountClone'],
                'Snaps -24 Hours': snap_calendar['last_24'],
                'Snaps -7 Days': snap_calendar['last_7'],
                'Snaps -30 Days': snap_calendar['last_30'],
                'Snaps 30-365 Days': snap_calendar['_30to365'],
                'Snaps older than 1yr': snap_calendar['older'],
                'Total Snaps': snap_calendar['all_snaps'],
                'Tag': tags[_]
            })

    return custom_rds_clusters_dict


def get_ebs_vols(region, ec2_conn, vol_status):
    volumes = []
    flat_volumes = []
    ebs_vol_list = []

    '''create paginator and build active ebs vols response dict'''

    print(f'{nl}Fetching EBS Volume Data from {region}...')
    pag = ec2_conn.get_paginator('describe_volumes')
    for page in pag.paginate(Filters=[
            {
                'Name': 'status',
                'Values': [vol_status]
            }
        ],
        PaginationConfig={
            'PageSize': 150
    }
    ):
        for i in page['Volumes']:
            volumes.append(i)
    for d in range(len(volumes)):
        flat_volumes.append(volumes[d])

    print(f'Found {len(flat_volumes)} EBS volumes in {region}')

    '''extract of all volumes IDs for subsequent snapshot query'''
    try:
        for i in range(len(flat_volumes)):
            ebs_vol_list.append(flat_volumes[i]['VolumeId'])
    except Exception as e:
        print(f'Failed to extract volume IDs:{nl}{e}')

    return ebs_vol_list, flat_volumes


def get_ebs_snapshots(region, ec2_conn, ebs_vol_list):
    ebs_snaps = []
    '''fetch all snapshots associated with active EBS vols'''
    p = Paginator(ebs_vol_list, 150)
    for i in p:
        try:
            response = ec2_conn.describe_snapshots(Filters=[
                {
                    'Name': 'volume-id',
                    'Values': i,
                }
            ])
            for i in response['Snapshots']:
                ebs_snaps.append(i)

        except Exception as e:
            print(f'Error locating EBS Snaps from {region}: {e}')

    return ebs_snaps


def get_orphan_ebs_snaps(ec2_conn, ebs_vol_list):
    response = []
    flat_response = []
    orphan_snaps = []

    print('\nFetching Orphan EBS Snapshot data...')

    pag = ec2_conn.get_paginator('describe_snapshots')
    for page in pag.paginate(OwnerIds=['self'],
                             PaginationConfig={'PageSize': 150}):
        for i in page['Snapshots']:
            response.append(i)

    '''flatten reponse structure'''
    for d in range(len(response)):
        flat_response.append(response[d])

    '''filter for orphans'''
    for s in flat_response:
        if s['VolumeId'] not in ebs_vol_list:
            orphan_snaps.append(s)

    return orphan_snaps


def analyze_engine_info(engine, engine_version, engine_mode):

    if engine_mode == "serverless":
        return False, False

    engine_version_parsed = engine_version.split(".")
    needs_upgrade = False

    try:
        if engine == "aurora" or engine == "aurora-mysql":
            major_version = (int(engine_version_parsed[0]), int(
                engine_version_parsed[1]))
            if major_version[0] != 5 or major_version[1] < 6:
                return False, False

            if major_version[1] == 6:
                needs_upgrade = engine_version < "5.6.mysql_aurora.1.19.2"
            elif major_version[1] == 7:
                needs_upgrade = engine_version < "5.7.mysql_aurora.2.04.4"

        elif engine == "mysql":
            major_version = (int(engine_version_parsed[0]), int(
                engine_version_parsed[1]))

            if major_version[0] == 5 and major_version[1] < 6:
                return False, False

            if major_version[1] == 6:
                needs_upgrade = engine_version < "5.6.40"
            elif major_version[1] == 7:
                needs_upgrade = engine_version < "5.7.24"
            elif major_version[1] == 8:
                needs_upgrade = engine_version < "8.0.13"

        elif engine == "postgres" or engine == "aurora-postgresql":
            major_version = (int(engine_version_parsed[0]), int(
                engine_version_parsed[1]))
            upgrade_targets = [((9, 4), 21), ((9, 5), 16),
                               ((9, 6), 12), ((10, 0), 7), ((11, 0), 2)]

            if major_version[0] > 11:
                return False, False

            elif major_version[0] == 9:
                for upgrade_target in upgrade_targets:
                    # ex: 9.6.12
                    if major_version[1] == upgrade_target[0][1] and int(engine_version_parsed[2]) < upgrade_target[1]:
                        needs_upgrade = True
                        break
            else:
                for upgrade_target in upgrade_targets:
                    # ex: 10.4
                    if major_version[0] == upgrade_target[0][0] and major_version[1] < upgrade_target[1]:
                        needs_upgrade = True
                        break
        else:
            return False, False
    except Exception:
        return False, False

    return True, needs_upgrade


def get_rds(region, rds_conn, rds_type):
    '''fetch RDS instances with paginator'''
    print(f'{nl}Fetching RDS instance Data from {region}...')
    response = []
    flat_response = []
    key = []
    arn_list = []
    target = []

    if rds_type == 'instance':
        target = 'describe_db_instances'
        key = 'DBInstances'
    elif rds_type == 'cluster':
        target = 'describe_db_clusters'
        key = 'DBClusters'

    pag = rds_conn.get_paginator(target)
    for page in pag.paginate(PaginationConfig={'PageSize': 100}):
        for i in page[key]:
            response.append(i)

    '''flatten response + add to dictionary'''
    for d in range(len(response)):
        flat_response.append(response[d])

    if rds_type == 'instance':
        for i in range(len(flat_response)):
            arn_list.append(flat_response[i]['DBInstanceArn'])
    else:
        for i in range(len(flat_response)):
            arn_list.append(flat_response[i]['DBClusterArn'])

    print(f'{nl}Found {len(flat_response)} RDS {rds_type}s in {region}')

    return flat_response


def connect_service(region, service, key_id=None, secret_key=None):
    '''connect client'''
    print(f'{nl}Attmpting connection to {service} in {region}')
    try:
        client = boto3.client(
            service,
            aws_access_key_id=key_id,
            aws_secret_access_key=secret_key,
            region_name=region
        )

        return client
    except Exception as e:
        print(f'{nl}Failed to connect to {service} in {region}:{nl}{e}')


def get_rds_clustersnaps(rds_conn, clusterID):
    response = rds_conn.describe_db_cluster_snapshots(
        DBClusterIdentifier=clusterID,
        MaxRecords=100,
    )
    return response['DBClusterSnapshots']


def get_rds_instancesnaps(rds_conn, instanceID):
    response = rds_conn.describe_db_snapshots(
        DBInstanceIdentifier=instanceID,
        MaxRecords=100,
    )
    return response['DBSnapshots']


def get_aurora_allocated(rds_conn, clusterID):
    response = rds_conn.describe_db_cluster_snapshots(
        DBClusterIdentifier=clusterID,
        SnapshotType='automated',
        MaxRecords=100,
    )
    return response['DBClusterSnapshots'][0]['AllocatedStorage']


def list_rds_tags(rds_conn, arn):
    try:
        response = rds_conn.list_tags_for_resource(ResourceName=arn)
    except Exception:
        response = None
    return response['TagList']


def catalog_snaps(snap_list, target_id, timefield):
    '''
    need to feed in a list off all snapshots in a given region
    to match against a list of volumes or rds instances
    '''
    snaptime_dict = []
    try:
        '''loop for parseing snapshot times + adding to snaptime dict'''
        now = datetime.datetime.utcnow()
        for x in range(len(snap_list)):
            last_24 = 0
            last_7 = 0
            last_30 = 0
            _30to365 = 0
            older = 0

            yesterday = (now - datetime.timedelta(days=1))
            lastweek = (now - datetime.timedelta(days=7))
            lastmonth = (now - datetime.timedelta(days=30))
            lastyear = (now - datetime.timedelta(days=365))

            try:
                snaptime = snap_list[x][timefield]
                snaptime = snaptime.replace(tzinfo=None)
            except Exception:
                continue

            if snaptime > yesterday:
                last_24 += 1
            if (snaptime > lastweek) and (snaptime < yesterday):
                last_7 += 1
            if (snaptime > lastmonth) and (snaptime < lastweek):
                last_30 += 1
            if snaptime < lastmonth and (snaptime < lastyear):
                _30to365 += 1
            if snaptime < lastyear:
                older += 1

            snaptime_dict.append({
                target_id: snap_list[x][target_id],
                'last_24': last_24,
                'last_7': last_7,
                'last_30': last_30,
                '_30to365': _30to365,
                'older': older
            })

    except Exception as e:
        print('''Failed to parse snapshot time
              data in catalog fuction \n''' + str(e))

    return snaptime_dict


def count_snaps(snaptime_dict, describe_response, index, target_id):
    '''
    describe response = your boto response for describe_db_instances
    or describe_volumes etc

    target id = the index within your describe response with the item
    to match against ie volume-id or db_instance_id etc
    '''
    last_24 = 0
    last_7 = 0
    last_30 = 0
    _30to365 = 0
    older = 0
    response = []

    try:
        for s in range(len(snaptime_dict)):
            if snaptime_dict[s][target_id] == \
                    describe_response[index][target_id]:
                last_24 += snaptime_dict[s]['last_24']
                last_7 += snaptime_dict[s]['last_7']
                last_30 += snaptime_dict[s]['last_30']
                _30to365 += snaptime_dict[s]['_30to365']
                older += snaptime_dict[s]['older']

    except Exception as e:
        print('failed to count snaps' + str(e))

    all_snaps = last_24 + last_7 + last_30 + older + _30to365
    '''wrap variables into dict'''
    response = {
        'last_24': last_24,
        'last_7': last_7,
        'last_30': last_30,
        '_30to365': _30to365,
        'older': older,
        'all_snaps': all_snaps
    }

    return response


def vol_block_pager(snap_id, ebs_conn):
    items = []
    response = ebs_conn.list_snapshot_blocks(
        SnapshotId=snap_id, MaxResults=5000)
    while True:
        if 'NextToken' in response:
            response = ebs_conn.list_snapshot_blocks(
                SnapshotId=snap_id,
                MaxResults=10000,
                NextToken=response['NextToken'])
            for i in response['Blocks']:
                items.append(i)
        if 'NextToken' not in response:
            return items


def vol_sizer(custom_ebs_dict, vol_id, ec2_conn, ebs_conn, cb):

    if cb == 'true' or cb == 'True':

        '''status updater'''
        length = len(custom_ebs_dict)
        if length % 10 == 0 and length != 0:
            print('''Still working. Parsed a total of ''' +
                  str(len(custom_ebs_dict)) + ' volumes')

        try:
            snap0_id = ec2_conn.describe_snapshots(Filters=[
                {
                    'Name': 'volume-id',
                    'Values': [vol_id],
                }
            ])['Snapshots'][0]['SnapshotId']
            blocks = vol_block_pager(snap0_id, ebs_conn)
            consumed_blocks = int(512 * len(blocks) / 1024 / 1024)
        except Exception:
            consumed_blocks = None
    else:
        consumed_blocks = None

    return consumed_blocks


def snap_sizer(ec2_conn, ebs_conn, ebs_snap_dict, vol_id, snap_id, cb):
    snap_gb_round = None

    if cb == 'true' or cb == 'True':
        '''status updater'''
        length = len(ebs_snap_dict)
        if length % 10 == 0 and length != 0:
            print('''Still working. Parsed a total of ''' +
                  str(len(ebs_snap_dict)) + ' snapshots')
        else:
            pass

        associated_snaps = ec2_conn.describe_snapshots(Filters=[
            {
                'Name': 'volume-id',
                'Values': [vol_id],
            }
        ])['Snapshots']

        for snap in range(len(associated_snaps)):
            if associated_snaps[snap] == associated_snaps[0]:
                blocks = vol_block_pager(snap_id, ebs_conn)
                snap_gb = 512 * len(blocks) / 1024 / 1024
                snap_gb_round = int(snap_gb)
            else:
                snap0 = associated_snaps[(snap-1)]['SnapshotId']
                snap1 = snap_id
                blocks = ebs_changed_block_pager(ebs_conn, snap0, snap1)
                snap_gb = 512 * len(blocks) / 1024 / 1024
                snap_gb_round = int(snap_gb)
    else:
        snap_gb_round = None

    return snap_gb_round


def ebs_changed_block_pager(ebs_conn, snap0, snap1):
    items = []
    response = ebs_conn.list_changed_blocks(
        FirstSnapshotId=snap0, SecondSnapshotId=snap1, MaxResults=5000)
    for i in response['ChangedBlocks']:
        items.append(i)
    while True:
        if 'NextToken' in response:
            response = ebs_conn.list_changed_blocks(
                FirstSnapshotId=snap0,
                SecondSnapshotId=snap1,
                MaxResults=10000,
                NextToken=response['NextToken'])
            for i in response['ChangedBlocks']:
                items.append(i)
        if 'NextToken' not in response:
            return items


def tag_parser(taglist):
    '''feed in the taglist from an ec2/ebs/snapshot reponse from boto
    ie reponse[volumes][i][tags]'''
    keylist = []
    try:
        for _ in range(len(taglist)):
            key = taglist[_]['Key']
            val = taglist[_]['Value']
            keylist.append(f'{key}: {val}')
        return keylist
    except Exception as e:
        print(f'no tags: {e}')
        return None


class Paginator:
    def __init__(self, iterable, page_len=3):
        self.iterable = iterable
        self.page_len = page_len

    def __iter__(self):
        page = []
        for i in self.iterable:
            page.append(i)
            if len(page) == self.page_len:
                yield page
                page = []
        if page:
            yield page
