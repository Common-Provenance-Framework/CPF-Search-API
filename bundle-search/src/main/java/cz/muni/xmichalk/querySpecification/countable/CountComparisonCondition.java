package cz.muni.xmichalk.querySpecification.countable;

import cz.muni.xmichalk.querySpecification.ICondition;

public class CountComparisonCondition<T> implements ICondition<T> {
    public ICountable<T> first;
    public EComparisonResult comparisonResult;
    public ICountable<T> second;

    public CountComparisonCondition() {
    }

    public CountComparisonCondition(ICountable<T> first, EComparisonResult comparisonResult, ICountable<T> second) {
        this.first = first;
        this.comparisonResult = comparisonResult;
        this.second = second;
    }

    public boolean test(T source) {
        if (first == null) {
            throw new IllegalStateException("Value of first cannot be null in " + this.getClass().getSimpleName());
        }
        if (comparisonResult == null) {
            throw new IllegalStateException(
                    "Value of comparisonResult cannot be null in " + this.getClass().getSimpleName());
        }
        if (second == null) {
            throw new IllegalStateException("Value of second cannot be null in " + this.getClass().getSimpleName());
        }

        int firstCount = first.count(source);
        int secondCount = second.count(source);

        return switch (comparisonResult) {
            case EComparisonResult.EQUALS -> firstCount == secondCount;
            case EComparisonResult.LESS_THAN -> firstCount < secondCount;
            case EComparisonResult.LESS_THAN_OR_EQUALS -> firstCount <= secondCount;
            case EComparisonResult.GREATER_THAN -> firstCount > secondCount;
            case EComparisonResult.GREATER_THAN_OR_EQUALS -> firstCount >= secondCount;
            default -> throw new IllegalStateException("Unexpected comparison result: " + comparisonResult);
        };
    }

}
