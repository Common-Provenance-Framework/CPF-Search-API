package cz.muni.xmichalk.querySpecification.logicalOperations;

import cz.muni.xmichalk.querySpecification.ICondition;

import java.util.List;

public class AllTrue<T> implements ICondition<T> {
    public List<ICondition<T>> conditions;

    public AllTrue() {
    }

    public AllTrue(List<ICondition<T>> conditions) {
        this.conditions = conditions;
    }

    @Override public boolean test(T target) {
        if (conditions == null || conditions.isEmpty()) {
            throw new IllegalStateException("Value of conditions cannot be null in " + this.getClass().getSimpleName());
        }
        return conditions.stream().allMatch(condition -> condition.test(target));
    }
}
