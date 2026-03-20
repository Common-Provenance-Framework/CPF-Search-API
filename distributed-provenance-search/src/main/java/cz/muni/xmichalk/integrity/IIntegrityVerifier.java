package cz.muni.xmichalk.integrity;

import cz.muni.xmichalk.dto.token.Token;
import org.openprovenance.prov.model.QualifiedName;

public interface IIntegrityVerifier {
    boolean verifyIntegrity(QualifiedName document, Token token);
}
