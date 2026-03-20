package cz.muni.xmichalk.models;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.INode;

public class DocumentStart {
    public CpmDocument document;
    public INode startNode;

    public DocumentStart() {
    }

    public DocumentStart(CpmDocument document, INode startNode) {
        this.document = document;
        this.startNode = startNode;
    }
}
