from django.db import migrations

def insert_default_roles(apps, schema_editor):

    Role = apps.get_model('accounts', 'Role')

    default_roles = [
        Role(role_id = 1, role_name = 'Employee'),
        Role(role_id = 2, role_name = 'Analyst'),
        Role(role_id = 3, role_name = 'Admin'),
    ]

    Role.objects.bulk_create(default_roles)

class Migration(migrations.Migration):

    dependencies = [('accounts', '0001_initial')]

    operations = [ migrations.RunPython(insert_default_roles)] 