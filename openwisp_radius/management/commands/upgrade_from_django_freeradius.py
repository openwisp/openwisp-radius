import json
import uuid

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.core.management import call_command
from django.core.management.base import BaseCommand
from swapper import get_model_name, load_model, split

User = get_user_model()
Organization = load_model('openwisp_users', 'Organization')


class BaseUpdateFromDjangoFreeradius(BaseCommand):
    help = 'Upgrade from django-freeradius'
    app_label_users = split(get_model_name('openwisp_users', 'Organization'))[0]
    app_label = split(get_model_name('openwisp_radius', 'Nas'))[0]

    def add_arguments(self, parser):
        parser.add_argument(
            '--backup',
            action='store',
            default=settings.BASE_DIR,
            help='(Optional) Path to the backup files',
        )
        parser.add_argument(
            '--organization',
            action='store',
            default=None,
            help=(
                '(Optional) organization UUID of the organization in '
                'which you want to import the data.'
            ),
        )

    def int_to_uuid(self, pk):
        return "00000000-0000-0000-0000-{:012}".format(pk)

    def _get_updated_permission_list(
        self, permission_data, permissions_list, contenttype_data
    ):
        permit_list = []
        for permit_pk in permissions_list:
            for item in permission_data:
                if item['pk'] == permit_pk:
                    for content in contenttype_data:
                        if item['fields']['content_type'] == content['pk']:
                            permit_app_label = content['fields']['app_label']
                            if permit_app_label == 'django_freeradius':
                                permit_app_label = self.app_label
                            elif (
                                content['fields']['model'] in ['user', 'group']
                                and permit_app_label == 'auth'
                            ):
                                permit_app_label = self.app_label_users
                    try:
                        permit_list.append(
                            Permission.objects.get(
                                content_type__app_label=permit_app_label,
                                codename=item['fields']['codename'],
                            ).pk
                        )
                    except Permission.DoesNotExist:  # pragma: nocover
                        pass
        return permit_list

    def handle(self, *args, **options):
        if options['organization']:
            org = Organization.objects.get(pk=options['organization'])
        else:
            org = Organization.objects.first()

        # Group Model
        with open(f'{options["backup"]}/contenttype.json') as contenttype:
            contenttype_data = json.load(contenttype)
        with open(f'{options["backup"]}/permission.json') as permission:
            permission_data = json.load(permission)
        with open(f'{options["backup"]}/group.json') as group:
            group_data = json.load(group)
        load_group_data = []
        for data in group_data:
            if not Group.objects.filter(name=data['fields']['name']).exists():
                load_group_data.append(
                    {
                        'model': f'{self.app_label_users}.group',
                        'pk': data['pk'] + Group.objects.count(),
                        'fields': {
                            'name': data['fields']['name'],
                            'permissions': self._get_updated_permission_list(
                                permission_data,
                                data['fields']['permissions'],
                                contenttype_data,
                            ),
                        },
                    }
                )
        if load_group_data:
            # Save in anotherfile
            with open(f'{options["backup"]}/group_loaded.json', 'w') as outfile:
                json.dump(load_group_data, outfile)
            # Load to database
            call_command(
                'loaddata', f'{options["backup"]}/group_loaded.json', verbosity=0
            )

        # User Model
        with open(f'{options["backup"]}/user.json') as users:
            users_data = json.load(users)
        # Make changes
        org_users_data = []
        load_users_data = []
        for data in users_data:
            data['model'] = f'{self.app_label_users}.user'
            data['pk'] = self.int_to_uuid(data['pk'])
            # If the user doesn't have an email, give them a
            # @example.com email but in openwisp-network-topology
            # email is UNIQUE.
            if not data['fields']['email']:
                data['fields']['email'] = f'{data["fields"]["username"]}@example.com'
            group_list = []
            for group_pk in data['fields']['groups']:
                for item in group_data:
                    if item['pk'] == group_pk:
                        group_list.append(
                            Group.objects.filter(name=item['fields']['name']).first().pk
                        )
            data['fields']['groups'] = group_list
            data['fields']['user_permissions'] = self._get_updated_permission_list(
                permission_data,
                data['fields']['user_permissions'],
                contenttype_data,
            )
            if not User.objects.filter(email=data['fields']['email']):
                load_users_data.append(data)
                if not data['fields']['is_superuser']:
                    org_users_data.append(
                        {
                            'model': f'{self.app_label_users}.organizationuser',
                            'pk': str(uuid.uuid4()),
                            'fields': {
                                'created': data['fields']['date_joined'],
                                'modified': data['fields']['date_joined'],
                                'is_admin': False,
                                'user': data['pk'],
                                'organization': str(org.pk),
                            },
                        }
                    )
        load_users_data.extend(org_users_data)
        if load_users_data:
            # Save in anotherfile
            with open(f'{options["backup"]}/user_loaded.json', 'w') as outfile:
                json.dump(load_users_data, outfile)
            # Load to database
            call_command(
                'loaddata', f'{options["backup"]}/user_loaded.json', verbosity=0
            )

        # Radius Models
        with open(f'{options["backup"]}/freeradius.json') as freeradius:
            freeradius_data = json.load(freeradius)
        # Make changes
        for data in freeradius_data:
            table_name = data["model"].split(".")[1]
            data['model'] = f'{self.app_label}.{table_name}'
            if table_name in [
                'radiuscheck',
                'radiusreply',
                'radiusgroup',
                'radiusbatch',
                'organizationradiussettings',
                'nas',
            ]:
                data['fields']['organization'] = str(org.pk)
            if table_name in ['radiusbatch']:
                del data['fields']['pdf']
                user_list = []
                for user in data['fields']['users']:
                    user_list.append(self.int_to_uuid(user))
                data['fields']['users'] = user_list
            if table_name in ['radiusreply', 'radiususergroup']:
                data['fields']['user'] = self.int_to_uuid(data['fields']['user'])
            if table_name in ['radiustoken']:
                data['fields']['user'] = self.int_to_uuid(data['fields']['user'])
                data['fields']['organization'] = str(org.pk)
        # Save in anotherfile
        with open(f'{options["backup"]}/freeradius_loaded.json', 'w') as outfile:
            json.dump(freeradius_data, outfile)
        # Load to database
        call_command(
            'loaddata', f'{options["backup"]}/freeradius_loaded.json', verbosity=0
        )
        # Load site.json & social.json
        call_command('loaddata', f'{options["backup"]}/site.json', verbosity=0)
        call_command('loaddata', f'{options["backup"]}/social.json', verbosity=0)

        self.stdout.write(self.style.SUCCESS('Migration Process Complete!'))


class Command(BaseUpdateFromDjangoFreeradius):
    pass
