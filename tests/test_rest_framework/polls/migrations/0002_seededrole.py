from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
        ("polls", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="SeededRole",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("template_key", models.CharField(max_length=150)),
                ("fingerprint", models.CharField(max_length=64)),
                ("detached", models.BooleanField(default=False)),
                ("modified", models.DateTimeField(auto_now=True)),
                (
                    "group",
                    models.OneToOneField(
                        on_delete=models.deletion.CASCADE,
                        related_name="seeded",
                        to="auth.group",
                    ),
                ),
            ],
        ),
    ]
