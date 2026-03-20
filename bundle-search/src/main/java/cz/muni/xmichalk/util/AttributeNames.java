package cz.muni.xmichalk.util;

import org.openprovenance.prov.vanilla.QualifiedName;

import static cz.muni.xmichalk.util.NameSpaceConstants.*;

public class AttributeNames {
    public static final QualifiedName ATTR_REFERENCED_BUNDLE_ID =
            new QualifiedName(CPM_URI, "referencedBundleId", "cpm");
    public static final QualifiedName ATTR_REFERENCED_META_BUNDLE_ID =
            new QualifiedName(CPM_URI, "referencedMetaBundleId", "cpm");
    public static final QualifiedName ATTR_REFERENCED_BUNDLE_HASH_VALUE =
            new QualifiedName(CPM_URI, "referencedBundleHashValue", "cpm");
    public static final QualifiedName ATTR_HASH_ALG = new QualifiedName(CPM_URI, "hashAlg", "cpm");
    public static final QualifiedName ATTR_PROVENANCE_SERVICE_URI =
            new QualifiedName(CPM_URI, "provenanceServiceUri", "cpm");

    public static final QualifiedName ATTR_START_TIME = new QualifiedName(PROV_URI, "startTime", "prov");
    public static final QualifiedName ATTR_END_TIME = new QualifiedName(PROV_URI, "startTime", "prov");
    public static final QualifiedName ATTR_LOCATION = new QualifiedName(PROV_URI, "location", "prov");
    public static final QualifiedName ATTR_PROV_TYPE = new QualifiedName(PROV_URI, "type", "prov");
    public static final QualifiedName ATTR_LABEL = new QualifiedName(PROV_URI, "label", "prov");

    public static final QualifiedName ATTR_VERSION = new QualifiedName(PAV_URI, "version", "pav");
}
