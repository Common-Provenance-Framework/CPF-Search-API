package cz.muni.xmichalk.querySpecification.logicalOperations;

import cz.muni.xmichalk.querySpecification.ICondition;

public class Negation<T> implements ICondition<T> {
    public ICondition<T> condition;

    public Negation() {
    }

    public Negation(ICondition<T> condition) {
        this.condition = condition;
    }

    @Override public boolean test(T target) {

        if (condition == null) {
            throw new IllegalStateException("Value of condition cannot be null in " + this.getClass().getSimpleName());
        }

        return !condition.test(target);
    }
}
