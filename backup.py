import click
import socket
import boto3
from datetime import datetime
import os
import stat
import errno
import subprocess
import time
import psycopg2
from passlib.hash import pbkdf2_sha256
import requests
from pathlib import Path


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
@click.option('--password', default='changeme',
              help='Replacement "password" for --strip-passwords')
@click.option('--sync-and-delete',
              help='Remote server to sync backup to; delete backup on success')
@click.option('--sleep', default=120,
              help='Seconds to sleep after modifying instance')
@click.option('--healthcheck',
              help='URL to ping for healthcheck')
@click.option('--source', default=lambda: socket.gethostname(),
              help='Label for identifying source of backup')
def backup(instance, database, sg, billto, profile, snapshot, fix_perms,
           strip_passwords, password, sync_and_delete, sleep, healthcheck,
           source):
    """
    This program makes a backup of an RDS instance from a snapshot.

    The arguments are the database instance to back up, the name of the
    database, and a security group that allows access from this machine.
    """
    backup_time = datetime.now()
    timestamp = backup_time.strftime('%Y%m%d%H%M%S')

    session = boto3.Session(profile_name=profile)
    client = session.client('rds')

    tags = [{'Key': 'Billable To',
             'Value': billto}]

    if snapshot:
        snapshot_id = f'dbb-{instance}-{timestamp}'
        print(f'Creating snapshot {snapshot_id}...')
        client.create_db_snapshot(
            DBSnapshotIdentifier=snapshot_id,
            DBInstanceIdentifier=instance,
            Tags=tags)
        latest = snapshot_id
        snaptime = backup_time
        waiter = client.get_waiter('db_snapshot_completed')
        waiter.wait(DBSnapshotIdentifier=snapshot_id)
        print('Snapshot created.')
    else:
        print('Identifying snapshots...')
        snapshots = client.describe_db_snapshots(
            DBInstanceIdentifier=instance,
            SnapshotType='automated')
        latest = max([s['DBSnapshotIdentifier']
                      for s in snapshots['DBSnapshots']
                      if s['DBSnapshotIdentifier']
                      .startswith(f'rds:{instance}')])
        print(f'Latest is {latest}')
        snaptime = datetime.strptime(latest, f'rds:{instance}-%Y-%m-%d-%H-%M')

    snap = snaptime.strftime('%Y%m%d%H%M%S')
    db_instance = f'{instance}-{timestamp}-fromsnap-{snap}'

    print(f'Restoring snapshot to instance {db_instance}')
    client.restore_db_instance_from_db_snapshot(
        DBInstanceIdentifier=db_instance,
        DBSnapshotIdentifier=latest,
        Tags=tags,
        CopyTagsToSnapshot=True)

    # wait for db to become available
    print('Waiting for instance to become available...')
    waiter = client.get_waiter('db_instance_available')
    waiter.wait(DBInstanceIdentifier=db_instance)

    print('Getting instance information...')
    instances = client.describe_db_instances(DBInstanceIdentifier=db_instance)
    db = instances['DBInstances'][0]
    engine = db['Engine']
    host = db['Endpoint']['Address']
    port = db['Endpoint']['Port']
    user = db['MasterUsername']

    print(f'Modifying instance with security group {sg}')
    client.modify_db_instance(
        DBInstanceIdentifier=db_instance,
        VpcSecurityGroupIds=[sg])

    # in some cases, the instance is not reachable immediately
    if sleep:
        print(f'Sleeping for {sleep} seconds')
        time.sleep(sleep)

    cwd = Path.cwd() / instance
    cwd.mkdir(exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    mode = stat.S_IRUSR | stat.S_IWUSR

    base = f'{db_instance}-{source}'

    print('Dumping database...')
    if engine == 'mysql':
        mycnf = Path.cwd() / f'.{instance}.my.cnf'
        print(f'Using {mycnf}')
        dumpfile = cwd / f'{base}.sql.xz'
        # https://stackoverflow.com/a/15015748/4074877
        with open(os.open(dumpfile, flags, mode), 'w') as f:
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
            subprocess.call(['xz',
                             '--stdout',
                             '-'],
                            stdin=dump.stdout, stdout=f)
            returncode = dump.wait()
    elif engine == 'postgres':
        # .pgpass in this directory must be set to 0600
        # the host entry for each possibility must be *
        # (psycopg2 does not have pg_dump functionality)
        pgpass = Path.cwd() / f'.{instance}.pgpass'
        print(f'Using {pgpass}')
        if strip_passwords:
            base = f'{base}-SAFE'
        dumpfile = cwd / f'{base}.dump'
        fd = os.open(dumpfile, flags, mode)
        os.close(fd)
        # in some cases (capstone) the master user does not have permissions
        # for the schema; in this case, we need to connect to the database and
        # issue the right permissions
        if fix_perms:
            c = f'passfile=/srv/backup/db/.pgpass dbname=capapi user=capstone host={host}'  # noqa
            (conn, cur) = connect(c)
            schema_to_group = 'SCHEMA capstone TO GROUP rds_superuser'
            privileges = [
                'ALL ON',
                'ALL PRIVILEGES ON ALL TABLES IN',
                'USAGE ON',
                'SELECT ON ALL SEQUENCES IN'
            ]
            for privilege in privileges:
                cur.execute(f'GRANT {privilege} {schema_to_group};')
            disconnect(conn, cur)
        # for devs, we don't want password hashes
        if strip_passwords:
            # customized to match previous hash
            custom_pbkdf2 = pbkdf2_sha256.using(rounds=150000)
            hash = custom_pbkdf2.hash(password)
            c = f'passfile={pgpass} dbname={database} user={user} host={host}'
            (conn, cur) = connect(c)
            # strip $ from front of hash
            cur.execute(f"update users set password='{hash[1:]}';")
            disconnect(conn, cur)
        # then we run pg_dump
        d = dict(os.environ)
        d['PGPASSFILE'] = str(pgpass)
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
                                      str(dumpfile)],
                                     env=d)

    # on success, sync and delete if necessary
    if returncode == 0:
        if sync_and_delete:
            print(f'Syncing backup file to {sync_and_delete}...')
            dest = f'{sync_and_delete}:/srv/backup/db/{instance}/'
            returncode = subprocess.call([
                'rsync', '--partial', str(dumpfile), dest
            ])
            # retry once if necessary
            if returncode != 0:
                print('First sync failed, resuming...')
                returncode = subprocess.call([
                    'rsync', '--append-verify', str(dumpfile), dest
                ])
            if returncode == 0:
                print(f'Done; deleting backup file {dumpfile}')
                dumpfile.unlink()
            else:
                print(f'Sync failed, *not* deleting backup file {dumpfile}')
    else:
        print('Dump failed.')
        if sync_and_delete:
            print(f'*Not* deleting backup file {dumpfile}')

    print(f'Deleting instance {db_instance}')
    client.delete_db_instance(
        DBInstanceIdentifier=db_instance,
        SkipFinalSnapshot=True
    )

    # is this necessary? the creation of the new instance also
    # produces another snapshot we might want to delete
    if snapshot:
        print('Deleting snapshot...')
        client.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id)

    if returncode == 0 and healthcheck:
        r = requests.get(healthcheck)
        if r.status_code != requests.codes.ok:
            print('Backup successful, but could not ping healthcheck.')

    print('Done.')


def connect(c):
    """ Connect to a PG database """
    conn = psycopg2.connect(c)
    cur = conn.cursor()
    return (conn, cur)


def disconnect(conn, cur):
    """ Disconnect from a PG database """
    conn.commit()
    cur.close()
    conn.close()


if __name__ == '__main__':
    backup()
