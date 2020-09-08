# Manually Created / Similar to freeradius 3 Database

import django.utils.timezone
import model_utils.fields
import swapper
from django.db import migrations, models

import openwisp_radius.base.models
import openwisp_users.mixins

from ..base.models import RAD_NAS_TYPES


class Migration(migrations.Migration):
    """
    Default schema of freeradius 3. openwisp-radius
    model's schema begins from next migration, this helps
    to enable users to migrate from freeradius 3
    """

    initial = True
    dependencies = [('openwisp_radius', '__first__')]

    operations = [
        migrations.CreateModel(
            name='Nas',
            fields=[
                (
                    'id',
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                (
                    'created',
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='created',
                    ),
                ),
                (
                    'modified',
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='modified',
                    ),
                ),
                (
                    'name',
                    models.CharField(
                        db_column='nasname',
                        db_index=True,
                        help_text='NAS Name (or IP address)',
                        max_length=128,
                        verbose_name='name',
                    ),
                ),
                (
                    'short_name',
                    models.CharField(
                        db_column='shortname', max_length=32, verbose_name='short name'
                    ),
                ),
                (
                    'type',
                    models.CharField(
                        default='other',
                        max_length=30,
                        verbose_name='type',
                        choices=RAD_NAS_TYPES,
                    ),
                ),
                (
                    'secret',
                    models.CharField(
                        help_text='Shared Secret', max_length=60, verbose_name='secret'
                    ),
                ),
                (
                    'ports',
                    models.PositiveIntegerField(
                        blank=True, null=True, verbose_name='ports'
                    ),
                ),
                (
                    'community',
                    models.CharField(
                        blank=True, max_length=50, null=True, verbose_name='community'
                    ),
                ),
                (
                    'description',
                    models.CharField(
                        blank=True,
                        max_length=200,
                        null=True,
                        verbose_name='description',
                    ),
                ),
                (
                    'server',
                    models.CharField(
                        blank=True, max_length=64, null=True, verbose_name='server'
                    ),
                ),
            ],
            options={
                'swappable': swapper.swappable_setting('openwisp_radius', 'Nas'),
                'db_table': 'nas',
                'verbose_name_plural': 'NAS',
                'abstract': False,
                'verbose_name': 'NAS',
            },
            bases=(openwisp_users.mixins.ValidateOrgMixin, models.Model),
        ),
        migrations.CreateModel(
            name='RadiusAccounting',
            fields=[
                (
                    'id',
                    models.BigAutoField(
                        db_column='radacctid', primary_key=True, serialize=False
                    ),
                ),
                (
                    'session_id',
                    models.CharField(
                        db_column='acctsessionid',
                        db_index=True,
                        max_length=64,
                        verbose_name='session ID',
                    ),
                ),
                (
                    'unique_id',
                    models.CharField(
                        db_column='acctuniqueid',
                        max_length=32,
                        unique=True,
                        verbose_name='accounting unique ID',
                    ),
                ),
                (
                    'username',
                    models.CharField(
                        blank=True,
                        db_index=True,
                        max_length=64,
                        null=True,
                        verbose_name='username',
                    ),
                ),
                (
                    'groupname',
                    models.CharField(
                        blank=True, max_length=64, null=True, verbose_name='group name'
                    ),
                ),
                (
                    'realm',
                    models.CharField(
                        blank=True, max_length=64, null=True, verbose_name='realm'
                    ),
                ),
                (
                    'nas_ip_address',
                    models.GenericIPAddressField(
                        db_column='nasipaddress',
                        db_index=True,
                        verbose_name='NAS IP address',
                    ),
                ),
                (
                    'nas_port_id',
                    models.CharField(
                        blank=True,
                        db_column='nasportid',
                        max_length=15,
                        null=True,
                        verbose_name='NAS port ID',
                    ),
                ),
                (
                    'nas_port_type',
                    models.CharField(
                        blank=True,
                        db_column='nasporttype',
                        max_length=32,
                        null=True,
                        verbose_name='NAS port type',
                    ),
                ),
                (
                    'start_time',
                    models.DateTimeField(
                        blank=True,
                        db_column='acctstarttime',
                        db_index=True,
                        null=True,
                        verbose_name='start time',
                    ),
                ),
                (
                    'stop_time',
                    models.DateTimeField(
                        blank=True,
                        db_column='acctstoptime',
                        db_index=True,
                        null=True,
                        verbose_name='stop time',
                    ),
                ),
                (
                    'session_time',
                    models.PositiveIntegerField(
                        blank=True,
                        db_column='acctsessiontime',
                        null=True,
                        verbose_name='session time',
                    ),
                ),
                (
                    'authentication',
                    models.CharField(
                        blank=True,
                        db_column='acctauthentic',
                        max_length=32,
                        null=True,
                        verbose_name='authentication',
                    ),
                ),
                (
                    'connection_info_start',
                    models.CharField(
                        blank=True,
                        db_column='connectinfo_start',
                        max_length=50,
                        null=True,
                        verbose_name='connection info start',
                    ),
                ),
                (
                    'connection_info_stop',
                    models.CharField(
                        blank=True,
                        db_column='connectinfo_stop',
                        max_length=50,
                        null=True,
                        verbose_name='connection info stop',
                    ),
                ),
                (
                    'input_octets',
                    models.BigIntegerField(
                        blank=True,
                        db_column='acctinputoctets',
                        null=True,
                        verbose_name='input octets',
                    ),
                ),
                (
                    'output_octets',
                    models.BigIntegerField(
                        blank=True,
                        db_column='acctoutputoctets',
                        null=True,
                        verbose_name='output octets',
                    ),
                ),
                (
                    'calling_station_id',
                    models.CharField(
                        blank=True,
                        db_column='callingstationid',
                        max_length=50,
                        null=True,
                        verbose_name='calling station ID',
                    ),
                ),
                (
                    'called_station_id',
                    models.CharField(
                        blank=True,
                        db_column='calledstationid',
                        max_length=50,
                        null=True,
                        verbose_name='called station ID',
                    ),
                ),
                (
                    'terminate_cause',
                    models.CharField(
                        blank=True,
                        db_column='acctterminatecause',
                        max_length=32,
                        null=True,
                        verbose_name='termination cause',
                    ),
                ),
                (
                    'service_type',
                    models.CharField(
                        blank=True,
                        db_column='servicetype',
                        max_length=32,
                        null=True,
                        verbose_name='service type',
                    ),
                ),
                (
                    'framed_protocol',
                    models.CharField(
                        blank=True,
                        db_column='framedprotocol',
                        max_length=32,
                        null=True,
                        verbose_name='framed protocol',
                    ),
                ),
                (
                    'framed_ip_address',
                    models.GenericIPAddressField(
                        blank=True,
                        db_column='framedipaddress',
                        db_index=True,
                        null=True,
                        verbose_name='framed IP address',
                    ),
                ),
                (
                    'update_time',
                    models.DateTimeField(
                        blank=True,
                        db_column='acctupdatetime',
                        null=True,
                        verbose_name='update time',
                    ),
                ),
                (
                    'interval',
                    models.IntegerField(
                        blank=True,
                        db_column='acctinterval',
                        null=True,
                        verbose_name='interval',
                    ),
                ),
            ],
            options={
                'swappable': 'OPENWISP_RADIUS_RADIUSACCOUNTING_MODEL',
                'db_table': 'radacct',
                'verbose_name_plural': 'accountings',
                'abstract': False,
                'verbose_name': 'accounting',
            },
            bases=(openwisp_users.mixins.ValidateOrgMixin, models.Model),
        ),
        migrations.CreateModel(
            name='RadiusCheck',
            fields=[
                (
                    'id',
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                (
                    'created',
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='created',
                    ),
                ),
                (
                    'modified',
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='modified',
                    ),
                ),
                (
                    'username',
                    models.CharField(
                        db_index=True, max_length=64, verbose_name='username'
                    ),
                ),
                ('value', models.CharField(max_length=253, verbose_name='value')),
                (
                    'op',
                    models.CharField(
                        choices=[
                            ('=', '='),
                            (':=', ':='),
                            ('==', '=='),
                            ('+=', '+='),
                            ('!=', '!='),
                            ('>', '>'),
                            ('>=', '>='),
                            ('<', '<'),
                            ('<=', '<='),
                            ('=~', '=~'),
                            ('!~', '!~'),
                            ('=*', '=*'),
                            ('!*', '!*'),
                        ],
                        default=':=',
                        max_length=2,
                        verbose_name='operator',
                    ),
                ),
                (
                    'attribute',
                    models.CharField(
                        choices=[
                            ('Max-Daily-Session', 'Max-Daily-Session'),
                            ('Max-All-Session', 'Max-All-Session'),
                            ('Max-Daily-Session-Traffic', 'Max-Daily-Session-Traffic'),
                            ('Cleartext-Password', 'Cleartext-Password'),
                            ('NT-Password', 'NT-Password'),
                            ('LM-Password', 'LM-Password'),
                            ('MD5-Password', 'MD5-Password'),
                            ('SMD5-Password', 'SMD5-Password'),
                            ('SHA-Password', 'SHA-Password'),
                            ('SSHA-Password', 'SSHA-Password'),
                            ('Crypt-Password', 'Crypt-Password'),
                        ],
                        default='NT-Password',
                        max_length=64,
                        verbose_name='attribute',
                    ),
                ),
            ],
            options={
                'swappable': 'OPENWISP_RADIUS_RADIUSCHECK_MODEL',
                'db_table': 'radcheck',
                'verbose_name_plural': 'checks',
                'abstract': False,
                'verbose_name': 'check',
            },
            bases=(
                openwisp_users.mixins.ValidateOrgMixin,
                openwisp_radius.base.models.AutoUsernameMixin,
                models.Model,
            ),
        ),
        migrations.CreateModel(
            name='RadiusGroupCheck',
            fields=[
                (
                    'id',
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                (
                    'created',
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='created',
                    ),
                ),
                (
                    'modified',
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='modified',
                    ),
                ),
                (
                    'groupname',
                    models.CharField(
                        db_index=True, max_length=64, verbose_name='group name'
                    ),
                ),
                (
                    'attribute',
                    models.CharField(max_length=64, verbose_name='attribute'),
                ),
                (
                    'op',
                    models.CharField(
                        choices=[
                            ('=', '='),
                            (':=', ':='),
                            ('==', '=='),
                            ('+=', '+='),
                            ('!=', '!='),
                            ('>', '>'),
                            ('>=', '>='),
                            ('<', '<'),
                            ('<=', '<='),
                            ('=~', '=~'),
                            ('!~', '!~'),
                            ('=*', '=*'),
                            ('!*', '!*'),
                        ],
                        default=':=',
                        max_length=2,
                        verbose_name='operator',
                    ),
                ),
                ('value', models.CharField(max_length=253, verbose_name='value')),
            ],
            options={
                'swappable': 'OPENWISP_RADIUS_RADIUSGROUPCHECK_MODEL',
                'db_table': 'radgroupcheck',
                'verbose_name_plural': 'group checks',
                'abstract': False,
                'verbose_name': 'group check',
            },
            bases=(openwisp_radius.base.models.AutoGroupnameMixin, models.Model),
        ),
        migrations.CreateModel(
            name='RadiusGroupReply',
            fields=[
                (
                    'id',
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                (
                    'created',
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='created',
                    ),
                ),
                (
                    'modified',
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='modified',
                    ),
                ),
                (
                    'groupname',
                    models.CharField(
                        db_index=True, max_length=64, verbose_name='group name'
                    ),
                ),
                (
                    'attribute',
                    models.CharField(max_length=64, verbose_name='attribute'),
                ),
                (
                    'op',
                    models.CharField(
                        choices=[('=', '='), (':=', ':='), ('+=', '+=')],
                        default='=',
                        max_length=2,
                        verbose_name='operator',
                    ),
                ),
                ('value', models.CharField(max_length=253, verbose_name='value')),
            ],
            options={
                'swappable': 'OPENWISP_RADIUS_RADIUSGROUPREPLY_MODEL',
                'db_table': 'radgroupreply',
                'verbose_name_plural': 'group replies',
                'abstract': False,
                'verbose_name': 'group reply',
            },
            bases=(openwisp_radius.base.models.AutoGroupnameMixin, models.Model),
        ),
        migrations.CreateModel(
            name='RadiusPostAuth',
            fields=[
                (
                    'id',
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                ('username', models.CharField(max_length=64, verbose_name='username')),
                (
                    'password',
                    models.CharField(
                        blank=True,
                        db_column='pass',
                        max_length=64,
                        verbose_name='password',
                    ),
                ),
                ('reply', models.CharField(max_length=32, verbose_name='reply')),
                (
                    'date',
                    models.DateTimeField(
                        auto_now_add=True, db_column='authdate', verbose_name='date'
                    ),
                ),
                (
                    'called_station_id',
                    models.CharField(
                        blank=True,
                        db_column='calledstationid',
                        max_length=50,
                        null=True,
                        verbose_name='called station ID',
                    ),
                ),
                (
                    'calling_station_id',
                    models.CharField(
                        blank=True,
                        db_column='callingstationid',
                        max_length=50,
                        null=True,
                        verbose_name='calling station ID',
                    ),
                ),
            ],
            options={
                'swappable': 'OPENWISP_RADIUS_RADIUSPOSTAUTH_MODEL',
                'db_table': 'radpostauth',
                'verbose_name_plural': 'post auth log',
                'abstract': False,
                'verbose_name': 'post auth',
            },
            bases=(openwisp_users.mixins.ValidateOrgMixin, models.Model),
        ),
        migrations.CreateModel(
            name='RadiusReply',
            fields=[
                (
                    'id',
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                (
                    'created',
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='created',
                    ),
                ),
                (
                    'modified',
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='modified',
                    ),
                ),
                (
                    'username',
                    models.CharField(
                        db_index=True, max_length=64, verbose_name='username'
                    ),
                ),
                ('value', models.CharField(max_length=253, verbose_name='value')),
                (
                    'op',
                    models.CharField(
                        choices=[('=', '='), (':=', ':='), ('+=', '+=')],
                        default='=',
                        max_length=2,
                        verbose_name='operator',
                    ),
                ),
                (
                    'attribute',
                    models.CharField(max_length=64, verbose_name='attribute'),
                ),
            ],
            options={
                'swappable': 'OPENWISP_RADIUS_RADIUSREPLY_MODEL',
                'db_table': 'radreply',
                'verbose_name_plural': 'replies',
                'abstract': False,
                'verbose_name': 'reply',
            },
            bases=(
                openwisp_users.mixins.ValidateOrgMixin,
                openwisp_radius.base.models.AutoUsernameMixin,
                models.Model,
            ),
        ),
        migrations.CreateModel(
            name='RadiusUserGroup',
            fields=[
                (
                    'id',
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                (
                    'created',
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='created',
                    ),
                ),
                (
                    'modified',
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='modified',
                    ),
                ),
                (
                    'username',
                    models.CharField(
                        db_index=True, max_length=64, verbose_name='username'
                    ),
                ),
                (
                    'groupname',
                    models.CharField(max_length=64, verbose_name='group name'),
                ),
                ('priority', models.IntegerField(default=1, verbose_name='priority')),
            ],
            options={
                'swappable': 'OPENWISP_RADIUS_RADIUSUSERGROUP_MODEL',
                'db_table': 'radusergroup',
                'verbose_name_plural': 'user groups',
                'abstract': False,
                'verbose_name': 'user group',
            },
            bases=(
                openwisp_radius.base.models.AutoGroupnameMixin,
                openwisp_radius.base.models.AutoUsernameMixin,
                models.Model,
            ),
        ),
    ]
