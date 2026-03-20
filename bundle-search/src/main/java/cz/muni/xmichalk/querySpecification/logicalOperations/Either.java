package cz.muni.xmichalk.querySpecification.logicalOperations;

import cz.muni.xmichalk.querySpecification.ICondition;

public class Either<T> implements ICondition<T> {
    public ICondition<T> first;
    public ICondition<T> second;

    public Either() {
    }

    public Either(ICondition<T> first, ICondition<T> second) {
        this.first = first;
        this.second = second;
    }

    @Override public boolean test(T item) {

        if (first == null) {
            throw new IllegalStateException("Value of first cannot be null in " + this.getClass().getSimpleName());
        }
        if (second == null) {
            throw new IllegalStateException("Value of second cannot be null in " + this.getClass().getSimpleName());
        }

        return first.test(item) ^ second.test(item);
    }
}
