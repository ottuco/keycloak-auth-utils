from django.db import models


class Poll(models.Model):
    question = models.CharField(max_length=200)

    def __str__(self):
        return self.question


class SeededRole(models.Model):
    """A consuming project's fingerprint record, as keycloak_utils.rbac.django needs.

    Lives in the project because the library ships no models: this is what a service
    adopting the shared seeder adds to its own app.
    """

    group = models.OneToOneField(
        "auth.Group", on_delete=models.CASCADE, related_name="seeded"
    )
    template_key = models.CharField(max_length=64)
    fingerprint = models.CharField(max_length=64)
    detached = models.BooleanField(default=False)
    modified = models.DateTimeField(auto_now=True)
