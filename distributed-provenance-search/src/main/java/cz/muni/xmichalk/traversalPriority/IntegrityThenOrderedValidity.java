package cz.muni.xmichalk.traversalPriority;

import cz.muni.xmichalk.models.ItemToTraverse;
import cz.muni.xmichalk.validity.EValidityCheck;

import java.util.Comparator;
import java.util.Map;

public class IntegrityThenOrderedValidity implements Comparator<ItemToTraverse> {
    public IntegrityThenOrderedValidity() {
    }

    @Override public int compare(ItemToTraverse first, ItemToTraverse second) {
        if (first == null && second != null) return 1;
        if (second == null && first != null) return -1;
        if (first == null) return 0;
        if (first.pathIntegrity && !second.pathIntegrity) {
            return -1;
        }
        if (!first.pathIntegrity && second.pathIntegrity) {
            return 1;
        }
        if (first.pathValidityChecks.size() != second.pathValidityChecks.size()) {
            throw new IllegalStateException("Count of validity checks does not match.");
        }

        for (int i = 0; i < first.pathValidityChecks.size(); i++) {
            Map.Entry<EValidityCheck, Boolean> firstCheck = first.pathValidityChecks.get(i);
            Map.Entry<EValidityCheck, Boolean> secondCheck = second.pathValidityChecks.get(i);
            if (firstCheck.getKey() != secondCheck.getKey()) {
                throw new IllegalStateException("Order of validity checks does not match.");
            }
            if (firstCheck.getValue() && !secondCheck.getValue()) {
                return -1;
            }
            if (!firstCheck.getValue() && secondCheck.getValue()) {
                return 1;
            }
        }

        return 0;
    }
}
