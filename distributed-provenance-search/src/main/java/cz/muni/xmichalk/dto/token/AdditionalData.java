package cz.muni.xmichalk.dto.token;

public record AdditionalData(
        String bundle, String hashFunction, String trustedPartyUri, String trustedPartyCertificate
) {
}