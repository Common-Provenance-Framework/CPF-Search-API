from django.db import models


class Organization(models.Model):
    org_name = models.CharField(max_length=40, primary_key=True)


class Certificate(models.Model):
    CERTIFICATE_TYPES = [("root", "root"), ("intermediate", "intermediate"), ("client", "client")]

    cert_digest = models.CharField(max_length=64, primary_key=True)
    cert = models.TextField()
    certificate_type = models.CharField(max_length=20, choices=CERTIFICATE_TYPES)
    is_revoked = models.BooleanField(default=False)
    received_on = models.IntegerField()

    organization = models.ForeignKey(Organization, on_delete=models.RESTRICT, default=None, null=True, to_field="org_name")


class Document(models.Model):
    DOCUMENT_TYPES = [("graph", "graph"),
                      ("domain_specific", "domain_specific"),
                      ("backbone", "backbone")]

    identifier = models.CharField()
    doc_format = models.TextField(null=True) # fix added format  - doc can have different formats
    certificate = models.ForeignKey(Certificate, on_delete=models.RESTRICT, to_field="cert_digest")
    organization = models.ForeignKey(Organization, on_delete=models.RESTRICT, to_field="org_name")
    document_type = models.CharField(max_length=20, choices=DOCUMENT_TYPES)
    document_text = models.TextField()
    created_on = models.IntegerField()
    signature = models.TextField(null=True)


class Token(models.Model):
    HASH_FUNCTIONS = [("SHA256", "SHA256"),
                      ("SHA512", "SHA512"),
                      ("SHA3-256", "SHA3-256"),
                      ("SHA3-512", "SHA3-512")]

    document = models.ForeignKey(Document, on_delete=models.RESTRICT)
    hash = models.CharField(max_length=128)
    hash_function = models.CharField(max_length=15, choices=HASH_FUNCTIONS)
    created_on = models.IntegerField()
    signature = models.TextField()
    jwt = models.TextField(null=True)
