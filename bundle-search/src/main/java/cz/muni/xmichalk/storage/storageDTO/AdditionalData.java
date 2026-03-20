package cz.muni.xmichalk.storage.storageDTO;

public record AdditionalData(
        String bundle, String hashFunction, String trustedPartyUri, String trustedPartyCertificate
) {
}