package cz.muni.xmichalk.querySpecification.countable;

public class CountConstant<T> implements ICountable<T> {
    public Integer count;

    public CountConstant() {
    }

    public CountConstant(int count) {
        this.count = count;
    }

    @Override public int count(T source) {
        if (count == null) {
            throw new IllegalStateException("Value of count cannot be null in " + this.getClass().getSimpleName());
        }

        return count;
    }
}
