package cz.muni.xmichalk.storage.storageDTO;

public record TokenData(
        String originatorId,
        String authorityId,
        long tokenTimestamp,
        long documentCreationTimestamp,
        String documentDigest,
        AdditionalData additionalData
) {
}