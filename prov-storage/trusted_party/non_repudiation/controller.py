import sys

import jcs
from django.db import transaction

from .models import Organization, Certificate, Document, Token
from OpenSSL import crypto
from trusted_party.settings import config
from datetime import datetime
from django.core.exceptions import ObjectDoesNotExist
import base64
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from prov.model import ProvDocument, ProvBundle

private_key = serialization.load_pem_private_key(config.private_key, password=None)


class IsNotSubgraph(Exception):
    pass


def retrieve_organizations():
    orgs = Organization.objects.all()

    out = []
    for org in orgs:
        cert, _ = get_sorted_certificates(org.org_name)
        o = {"id": org.org_name, "certificate": cert.cert}

        out.append(o)

    return out


def retrieve_organization(org_id, include_revoked=False):
    org = Organization.objects.filter(org_name=org_id).first()

    # fix - added .first() and check for None
    # if org is None => raise ObjectDoesNotExist
    # otherwise if org is None and we try to access org.org_name
    # it will throw an NullPointerException that is not handled and does not return the expected 404 response with error message
    # but 500 - Internal Server Error!!
    if org is None:
        raise ObjectDoesNotExist(f"Organization with id [{org_id}] does not exist!")

    active_cert, revoked = get_sorted_certificates(org.org_name)

    out = {"id": org.org_name, "certificate": active_cert.cert}

    if include_revoked:
        if len(revoked) != 0:
            out.update({"revokedCertificates": [r.cert for r in revoked]})

    return out


def get_sorted_certificates(org_id):
    revoked_certs = list(
        Certificate.objects.filter(
            organization=org_id, certificate_type="client", is_revoked=True
        ).all()
    )
    active_cert = Certificate.objects.filter(
        organization=org_id, certificate_type="client", is_revoked=False
    ).first()

    return active_cert, revoked_certs


def verify_chain_of_trust(client_cert, intermediate_certs: list):
    serialized_client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, client_cert)

    store = crypto.X509Store()

    serialized_intermediate_certs = []
    for cert in intermediate_certs:
        serialized_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        serialized_intermediate_certs.append(serialized_cert)

    for cert in config.trusted_certs:
        serialized_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        store.add_cert(serialized_cert)

    store_ctx = crypto.X509StoreContext(
        store, serialized_client_cert, serialized_intermediate_certs
    )
    store_ctx.verify_certificate()


# change - transaction
@transaction.atomic
def store_organization(org_id, client_cert, intermediate_certs):
    org = Organization()
    org.org_name = org_id
    org.save()

    serialized_client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, client_cert)
    c = Certificate()
    c.cert_digest = (
        serialized_client_cert.digest("sha256").decode("utf-8").replace(":", "")
    )
    c.cert = client_cert
    c.certificate_type = "client"
    c.is_revoked = False
    c.received_on = int(datetime.now().timestamp())
    c.organization = org
    c.save()

    for cert in intermediate_certs:
        serialized_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

        c = Certificate()
        c.cert_digest = (
            serialized_cert.digest("sha256").decode("utf-8").replace(":", "")
        )
        c.cert = cert
        c.certificate_type = "intermediate"
        c.is_revoked = False
        c.received_on = int(datetime.now().timestamp())
        c.organization = org
        c.save()


# change - transaction
@transaction.atomic
def update_certificate(org_id, client_cert, intermediate_certs):
    revoke_all_stored_certificates(org_id)

    org = Organization.objects.get(org_name=org_id)

    serialized_client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, client_cert)
    c = Certificate()
    c.cert_digest = (
        serialized_client_cert.digest("sha256").decode("utf-8").replace(":", "")
    )
    c.cert = client_cert
    c.certificate_type = "client"
    c.is_revoked = False
    c.received_on = int(datetime.now().timestamp())
    c.organization = org
    c.save()

    for cert in intermediate_certs:
        serialized_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

        digest = serialized_cert.digest("sha256").decode("utf-8").replace(":", "")
        try:
            c = Certificate.objects.get(cert_digest=digest)
            c.is_revoked = False
            c.save()
        except ObjectDoesNotExist:
            c = Certificate()
            c.cert_digest = digest
            c.cert = cert
            c.certificate_type = "intermediate"
            c.is_revoked = False
            c.received_on = int(datetime.now().timestamp())
            c.organization = org
            c.save()


# change - transaction
@transaction.atomic
def revoke_all_stored_certificates(org_id):
    client_certs = list(
        Certificate.objects.filter(organization=org_id, certificate_type="client").all()
    )
    intermediate_certs = list(
        Certificate.objects.filter(
            organization=org_id, certificate_type="intermediate"
        ).all()
    )

    for cert in client_certs:
        if not cert.is_revoked:
            cert.is_revoked = True
            cert.save()

    for cert in intermediate_certs:
        if not cert.is_revoked:
            cert.is_revoked = True
            cert.save()


def retrieve_document(org_id, doc_id, doc_format="json"):
    org = Organization.objects.filter(org_name=org_id).first()  # fix - added .first()
    doc = Document.objects.filter(organization=org, identifier=doc_id, doc_format=doc_format).first()  #  fix - added .first()

    return doc


def retrieve_tokens(org_id, token_format="json"):
    org = Organization.objects.filter(org_name=org_id).first()
    docs = Document.objects.filter(organization=org).all()

    tokens = {}
    for doc in docs:
        tokens[doc] = Token.objects.filter(document=doc).all()

    tokens_out = []
    for doc, tokens in tokens.items():
        for token in tokens:
            tokens_out.append(
                _serialize_existing_token(token, doc, org.org_name, token_format)
            )

    return tokens_out


# change - doc_format added
def retrieve_specific_token(org_id, doc_id, doc_type="graph", doc_format="json", token_format="json"):
    org = Organization.objects.get(org_name=org_id)
    doc = Document.objects.get(
        organization=org, identifier=doc_id, document_type=doc_type, doc_format=doc_format
    )
    tokens = Token.objects.filter(document=doc).all()

    tokens_out = []
    for token in tokens:
        tokens_out.append(_serialize_existing_token(token, doc, org.org_name, token_format))

    return tokens_out if len(tokens_out) > 1 else tokens_out[0]


def verify_signature(json_data):
    org_id = json_data["organizationId"]
    graph = json_data["document"]
    signature = json_data["signature"]

    org = Organization.objects.filter(org_name=org_id).first()
    cert = Certificate.objects.filter(
        organization=org, is_revoked=False, certificate_type="client"
    ).first()

    loaded_cert = load_pem_x509_certificate(
        cert.cert.encode("utf-8"), backend=default_backend()
    )
    public_key = loaded_cert.public_key()

    public_key.verify(
        base64.b64decode(signature), base64.b64decode(graph), ec.ECDSA(hashes.SHA256())
    )


def _build_jwt_token_parts_from_values(
    originator_id, bundle_id, document_creation_timestamp, document_hash, token_timestamp
):
    payload = {
        "originatorId": originator_id,
        "authorityId": config.id,
        "tokenTimestamp": token_timestamp, # TODO: Use clear claims like iss, iat, jti
        "documentCreationTimestamp": document_creation_timestamp,
        "documentDigest": document_hash,
    }

    header = {
        "alg": "ES256",
        "typ": "JWT",
        "bundle": bundle_id,
        "hashFunction": "SHA256",
        "trustedPartyUri": config.fqdn,
        "trustedPartyCertificate": config.cert, # TODO: This should be KID not entire certificate because token size matters!!
    }

    return header, payload


def _build_jwt_token_parts(json_data, bundle_id, token_timestamp):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(base64.b64decode(json_data["document"]))
    document_hash = digest.finalize().hex()

    return _build_jwt_token_parts_from_values(
        json_data["organizationId"],
        bundle_id,
        json_data["createdOn"],
        document_hash,
        token_timestamp,
    )


def _serialize_jwt(header, payload):
    def _to_base64url(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    encoded_header = _to_base64url(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    encoded_payload = _to_base64url(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )

    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    der_signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    jose_signature = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")
    encoded_signature = _to_base64url(jose_signature)

    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def get_serialized_json_token(json_data, bundle_id, token_timestamp):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(base64.b64decode(json_data["document"]))
    hash = digest.finalize().hex()

    serialized_token = {
        "data": {
            "originatorId": json_data["organizationId"],
            "authorityId": config.id,
            "tokenTimestamp": token_timestamp,
            "documentCreationTimestamp": json_data["createdOn"],
            "documentDigest": hash,
            "additionalData": {
                "bundle": bundle_id,
                "hashFunction": "SHA256",
                "trustedPartyUri": config.fqdn,
                "trustedPartyCertificate": config.cert,
            },
        }
    }

    signature = private_key.sign(
        jcs.canonicalize(serialized_token["data"]), ec.ECDSA(hashes.SHA256())
    )

    serialized_token.update({"signature": base64.b64encode(signature).decode("utf-8")})

    return serialized_token


def create_new_token(json_data, doc: Document, token_format):
    token_timestamp = int(datetime.now().timestamp())

    serialized_token = get_serialized_json_token(json_data, doc.identifier, token_timestamp)
    jwt_token = get_serialized_jwt_token(json_data, doc.identifier, token_timestamp)

    t = Token()
    t.hash = serialized_token["data"]["documentDigest"]
    t.hash_function = serialized_token["data"]["additionalData"]["hashFunction"]
    t.document = doc
    t.created_on = serialized_token["data"]["tokenTimestamp"]
    t.signature = serialized_token["signature"]
    t.jwt = jwt_token
    t.save()

    return serialized_token if token_format == "json" else jwt_token

def _serialize_existing_token(token, doc, org_id, token_format):
    return _serialize_existing_json_token(token, doc, org_id) if token_format == "json" else _serialize_existing_jwt_token(token, doc, org_id)

def _serialize_existing_jwt_token(token, doc, org_id):
    if token.jwt is not None:
        return token.jwt

    header, payload = _build_jwt_token_parts_from_values(
        org_id,
        doc.identifier,
        doc.created_on,
        token.hash,
        token.created_on,
    )
    return _serialize_jwt(header, payload)

def _serialize_existing_json_token(token, doc, org_id):
    t = {
        "data": {
            "originatorId": org_id,
            "authorityId": config.id,
            "tokenTimestamp": token.created_on,
            "documentCreationTimestamp": doc.created_on,
            "documentDigest": token.hash,
            "additionalData": {
                "bundle": doc.identifier,
                "hashFunction": token.hash_function,
                "trustedPartyUri": config.fqdn,
                "trustedPartyCertificate": config.cert,
            },
        },
        "signature": token.signature,
    }

    return t

def get_serialized_jwt_token(json_data, bundle_id, token_timestamp):
    header, payload = _build_jwt_token_parts(json_data, bundle_id, token_timestamp)
    return _serialize_jwt(header, payload)

def check_is_subgraph(prov_bundle: ProvBundle, prov_bundle_original: ProvBundle):
    """try:
        original_graph_token = retrieve_specific_token(
            request_json_data["organizationId"], prov_bundle.identifier.uri)
    except ObjectDoesNotExist:
        return False"""
    # check whether prov_bundle is subgraph of prov_bundle_original
    return None


# change - transaction
@transaction.atomic
def issue_token_and_store_doc(json_data, token_format="json"):
    graph = base64.b64decode(json_data["document"])
    prov_document = ProvDocument.deserialize(
        content=graph, format=json_data["documentFormat"]
    )

    assert len(prov_document.bundles) == 1, "Only one bundle expected in the document!"
    prov_bundle = list(prov_document.bundles)[0]

    if json_data["type"] in ("domain_specific", "backbone"):
        # retrieve original component from database, deserialize it, call check_is_subgraph with bundle being saved and original one
        prov_bundle_original = ...
        check_is_subgraph(prov_bundle, prov_bundle_original)

    if json_data["type"] == "meta":
        time_stamp = int(datetime.now().timestamp())
        return get_serialized_json_token(json_data, prov_bundle.identifier.uri, time_stamp) if token_format == "json" else get_serialized_jwt_token(json_data, prov_bundle.identifier.uri, time_stamp)

    try:
        # change - documentFormat also used to retrieve token
        tokens = retrieve_specific_token(
            json_data["organizationId"], prov_bundle.identifier.uri, json_data["type"], json_data["documentFormat"], token_format
        )

        return tokens

    except ObjectDoesNotExist:
        org = Organization.objects.filter(org_name=json_data["organizationId"]).first()
        cert = Certificate.objects.filter(organization=org, is_revoked=False).first()

        d = Document()
        d.identifier = prov_bundle.identifier.uri
        d.doc_format = json_data["documentFormat"]
        d.certificate = cert
        d.organization = org
        d.document_type = json_data["type"]
        d.document_text = json_data["document"]
        d.created_on = json_data["createdOn"]
        if json_data["type"] == "graph":
            d.signature = json_data["signature"]
        else:
            d.signature = None
        d.save()

        return create_new_token(json_data, d, token_format)
