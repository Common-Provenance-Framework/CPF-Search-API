package cz.muni.xmichalk.models;

import cz.muni.xmichalk.storage.storageDTO.Token;

public class QueryResult<T> {
    public Token token;
    public T result;

    public QueryResult() {
    }

    public QueryResult(T result, Token token) {
        this.token = token;
        this.result = result;
    }
}