# Generated by Django 3.2.18 on 2023-05-03 09:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('trench', '0005_remove_mfamethod_primary_is_active_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mfamethod',
            name='id',
            field=models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
    ]