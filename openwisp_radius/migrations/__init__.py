from django.conf import settings

def add_default_organization(apps, schema_editor):
    """
    Set default organization using 
    settings._OPENWISP_DEFAULT_ORG_UUID
    """
    Models = ['nas', 'radiusaccounting', 'radiuscheck', 'radiuspostauth', 'radiusreply']
    
    for Model in Models:
        Table = apps.get_model('openwisp_radius', Model)
        for record in Table.objects.all().iterator():
            record.organization_id = settings._OPENWISP_DEFAULT_ORG_UUID
            record.save()
