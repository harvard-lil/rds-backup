import click
import boto3
from datetime import datetime
import os
import stat
import errno
import subprocess
import psycopg2
import requests


@click.command()
@click.argument('instance')
@click.argument('database')
@click.argument('sg')
@click.option('--billto', default='lil',
              help='Value of "Billable To" tag')
@click.option('--profile', default='default',
              help='Profile for connecting to AWS')
@click.option('--snapshot/--no-snapshot', default=False,
              help='Take a snapshot; ONLY USE WITH MULTI-AZ INSTANCES!')
@click.option('--fix-perms/--no-fix-perms', default=False,
              help='Handle permissions problem for the CAP API')
@click.option('--strip-passwords/--no-strip-passwords', default=False,
              help='Overwrite passwords, emit zipped SQL dump; PG only')
@click.option('--sync-and-delete',
              help='Remote server to sync backup to; delete backup on success')
@click.option('--healthcheck',
              help='URL to ping for healthcheck')
def backup(instance, database, sg, billto, profile, snapshot, fix_perms,
           strip_passwords, sync_and_delete, healthcheck):
    """
    Run like this:

    python backup.py <RDS instance> <database> <security group>
    """
    backup_time = datetime.now()
    timestamp = backup_time.strftime('%Y%m%d%H%M%S')

    session = boto3.Session(profile_name=profile)
    client = session.client('rds')

    if snapshot:
        snapshot_id = f'dbb-{instance}-{timestamp}'
        print(f'Creating snapshot {snapshot_id}...')
        response = client.create_db_snapshot(
            DBSnapshotIdentifier=snapshot_id,
            DBInstanceIdentifier=instance,
            Tags=[
                {
                    'Key': 'Billable To',
                    'Value': billto
                }
            ])
        latest = snapshot_id
        snaptime = backup_time
        waiter = client.get_waiter('db_snapshot_completed')
        waiter.wait(DBSnapshotIdentifier=snapshot_id)
        print('Snapshot created.')
    else:
        print('Identifying snapshots...')
        response = client.describe_db_snapshots(
            DBInstanceIdentifier=instance,
            SnapshotType='automated')
        latest = max([s['DBSnapshotIdentifier']
                      for s in response['DBSnapshots']
                      if s['DBSnapshotIdentifier']
                      .startswith(f'rds:{instance}')])
        print(f'Latest is {latest}')
        snaptime = datetime.strptime(latest, f'rds:{instance}-%Y-%m-%d-%H-%M')

    snap = snaptime.strftime('%Y%m%d%H%M%S')
    db_instance = f'{instance}-{timestamp}-fromsnap-{snap}'

    print(f'Restoring snapshot to instance {db_instance}')
    response2 = client.restore_db_instance_from_db_snapshot(  # noqa
        DBInstanceIdentifier=db_instance,
        DBSnapshotIdentifier=latest,
        Tags=[
            {
                'Key': 'Billable To',
                'Value': billto
            }
        ],
        CopyTagsToSnapshot=True)

    # wait for db to become available
    print('Waiting for instance to become available...')
    waiter = client.get_waiter('db_instance_available')
    waiter.wait(DBInstanceIdentifier=db_instance)

    print('Getting instance information...')
    response3 = client.describe_db_instances(DBInstanceIdentifier=db_instance)
    db = response3['DBInstances'][0]
    engine = db['Engine']
    host = db['Endpoint']['Address']
    port = db['Endpoint']['Port']
    user = db['MasterUsername']

    print(f'Modifying instance with security group {sg}')
    response4 = client.modify_db_instance(  # noqa
        DBInstanceIdentifier=db_instance,
        VpcSecurityGroupIds=[sg])

    try:
        os.makedirs(os.path.join(os.getcwd(), instance))
        print(f'Created directory {instance}')
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    mode = stat.S_IRUSR | stat.S_IWUSR

    print('Dumping database...')
    if engine == 'mysql':
        dumpfile = f'{db_instance}.sql.xz'
        mycnf = os.path.join(os.getcwd(), f'.{instance}.my.cnf')
        # https://stackoverflow.com/a/15015748/4074877
        with os.fdopen(os.open(os.path.join(os.getcwd(), instance, dumpfile),
                               flags,
                               mode),
                       'w') as f:
            print(f'Using {mycnf}')
            dump = subprocess.Popen(['mysqldump',
                                     f'--defaults-extra-file={mycnf}',
                                     '--single-transaction',
                                     '--databases',
                                     database,
                                     '-h',
                                     host,
                                     '-u',
                                     user,
                                     '-P',
                                     str(port)],
                                    stdout=subprocess.PIPE)
            compress = subprocess.call(['xz',  # noqa
                                        '--stdout',
                                        '-'],
                                       stdin=dump.stdout, stdout=f)
            returncode = dump.wait()
    elif engine == 'postgres':
        # .pgpass in this directory must be set to 0600
        # the host entry for each possibility must be *
        # (psycopg2 does not have pg_dump functionality)
        pgpass = os.path.join(os.getcwd(), f'.{instance}.pgpass')
        print(f'Using {pgpass}')
        dumpfile = os.path.join(os.getcwd(),
                                instance,
                                f'{db_instance}.dump')
        fd = os.open(dumpfile, flags, mode)
        os.close(fd)
        # in some cases (capstone) the master user does not have permissions
        # for the schema; in this case, we need to connect to the database and
        # issue the right permissions
        if fix_perms:
            c = f'passfile=/srv/backup/db/.pgpass dbname=capapi user=capstone host={host}'  # noqa
            conn = psycopg2.connect(c)
            cur = conn.cursor()
            cur.execute("GRANT ALL ON SCHEMA capstone TO GROUP rds_superuser;")
            cur.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA capstone TO GROUP rds_superuser;")  # noqa
            cur.execute("GRANT USAGE ON SCHEMA capstone TO GROUP rds_superuser;")  # noqa
            cur.execute("GRANT SELECT ON ALL SEQUENCES IN SCHEMA capstone TO GROUP rds_superuser;")  # noqa
            conn.commit()
            cur.close()
            conn.close()
        # for devs, we don't want password hashes
        if strip_passwords:
            c = f'passfile={pgpass} dbname={database} user={user} host={host}'
            conn = psycopg2.connect(c)
            cur = conn.cursor()
            cur.execute("update users set password='pbkdf2_sha256$150000$BuWRnNWV94Tj$281UbOQleCUCi6/Bb1i+NpmlZ0/ptqwtvycVaegFZiY=';")  # noqa
            conn.commit()
            cur.close()
            conn.close()
        # then we run pg_dump
        d = dict(os.environ)
        d['PGPASSFILE'] = pgpass
        returncode = subprocess.call(['pg_dump',
                                      '-Fc',
                                      database,
                                      '-h',
                                      host,
                                      '-p',
                                      str(port),
                                      '-U',
                                      user,
                                      '-w',
                                      '-f',
                                      dumpfile],
                                     env=d)

    # on success, sync and delete if necessary
    if returncode == 0:
        if sync_and_delete:
            returncode = subprocess.call(['scp',
                                          dumpfile,
                                          f'{sync_and_delete}'])
    else:
        print(f'Dump failed.')
        if sync_and_delete:
            print(f'*Not* deleting backup file {dumpfile}')
        

    print(f'Deleting instance {db_instance}')
    response5 = client.delete_db_instance(  # noqa
        DBInstanceIdentifier=db_instance,
        SkipFinalSnapshot=True
    )

    # is this necessary? the creation of the new instance also
    # produces another snapshot we might want to delete
    if snapshot:
        print('Deleting snapshot...')
        response6 = client.delete_db_snapshot(  # noqa
            DBSnapshotIdentifier=snapshot_id)

    print('Done.')

    if returncode == 0 and healthcheck:
        r = requests.get(healthcheck)
        if r.status_code != requests.codes.ok:
            print('Backup successful, but could not ping healthcheck.')


if __name__ == '__main__':
    backup()
