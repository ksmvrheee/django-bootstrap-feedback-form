# Generated by Django 5.1

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='FeedbackFormSession',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('session_identifier', models.CharField(max_length=255)),
                ('email_hash', models.CharField(max_length=128)),
                ('confirmation_code_hash', models.CharField(max_length=128)),
                ('resending_attempts_left', models.IntegerField(default=2)),
                ('validation_attempts_left', models.IntegerField(default=10)),
                ('submission_attempts_left', models.IntegerField(default=3)),
                ('cooldown_expiry', models.DateTimeField()),
                ('confirmation_code_expiry', models.DateTimeField()),
            ],
        ),
    ]
